/*
symflux - Symetric Distributed Database Synchronization Library - A minor fork of conflux
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

symflux is a slightly modified version of conflux(https://github.com/cmars/conflux) by Casey Marshall, copyright 2013(GNU GPL v3).

This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package recon

import (
	"errors"

	. "github.com/pruthvirajsinh/symflux"
)

type PrefixTree interface {
	Init()
	Create() error
	Drop() error
	Close() error
	SplitThreshold() int
	JoinThreshold() int
	BitQuantum() int
	NumSamples() int
	Points() []*Zp
	Root() (PrefixNode, error)
	Node(key *Bitstring) (PrefixNode, error)
	Insert(z *Zp) error
	Remove(z *Zp) error
}

type PrefixNode interface {
	BitQuantum() int
	Parent() (PrefixNode, bool)
	Key() *Bitstring
	Elements() []*Zp
	Size() int
	Children() []PrefixNode
	SValues() []*Zp
	IsLeaf() bool
}

const DefaultThreshMult = 10
const DefaultBitQuantum = 2
const DefaultMBar = 5
const DefaultSplitThreshold = DefaultThreshMult * DefaultMBar
const DefaultJoinThreshold = DefaultSplitThreshold / 2
const DefaultNumSamples = DefaultMBar + 1

var ErrSamplePointElement = errors.New("Sample point added to elements")
var ErrUnexpectedLeafNode = errors.New("Unexpected leaf node")

type MemPrefixTree struct {
	// Tree configuration options
	splitThreshold int
	joinThreshold  int
	bitQuantum     int
	mBar           int
	numSamples     int
	// Sample data points for interpolation
	points []*Zp
	// Tree's root node
	root *MemPrefixNode
}

func (t *MemPrefixTree) SplitThreshold() int       { return t.splitThreshold }
func (t *MemPrefixTree) JoinThreshold() int        { return t.joinThreshold }
func (t *MemPrefixTree) BitQuantum() int           { return t.bitQuantum }
func (t *MemPrefixTree) NumSamples() int           { return t.numSamples }
func (t *MemPrefixTree) Points() []*Zp             { return t.points }
func (t *MemPrefixTree) Root() (PrefixNode, error) { return t.root, nil }

// Init configures the tree with default settings if not already set,
// and initializes the internal state with sample data points, root node, etc.
func (t *MemPrefixTree) Init() {
	if t.bitQuantum == 0 {
		t.bitQuantum = DefaultBitQuantum
	}
	if t.splitThreshold == 0 {
		t.splitThreshold = DefaultSplitThreshold
	}
	if t.joinThreshold == 0 {
		t.joinThreshold = DefaultJoinThreshold
	}
	if t.mBar == 0 {
		t.mBar = DefaultMBar
	}
	if t.numSamples == 0 {
		t.numSamples = DefaultNumSamples
	}
	t.points = Zpoints(P_SKS, t.numSamples)
	t.Create()
}

func (t *MemPrefixTree) Create() error {
	t.root = new(MemPrefixNode)
	t.root.init(t)
	return nil
}

func (t *MemPrefixTree) Drop() error {
	t.root = new(MemPrefixNode)
	t.root.init(t)
	return nil
}

func (t *MemPrefixTree) Close() error { return nil }

func Find(t PrefixTree, z *Zp) (PrefixNode, error) {
	bs := NewZpBitstring(z)
	return t.Node(bs)
}

func AddElementArray(t PrefixTree, z *Zp) (marray []*Zp, err error) {
	points := t.Points()
	marray = make([]*Zp, len(points))
	for i := 0; i < len(points); i++ {
		marray[i] = Z(z.P).Sub(points[i], z)
		if marray[i].IsZero() {
			err = ErrSamplePointElement
			return
		}
	}
	return
}

func DelElementArray(t PrefixTree, z *Zp) (marray []*Zp) {
	points := t.Points()
	marray = make([]*Zp, len(points))
	for i := 0; i < len(points); i++ {
		marray[i] = Z(z.P).Sub(points[i], z).Inv()
	}
	return
}

func (t *MemPrefixTree) Node(bs *Bitstring) (PrefixNode, error) {
	node := t.root
	nbq := t.BitQuantum()
	for i := 0; i < bs.BitLen() && !node.IsLeaf(); i += nbq {
		childIndex := 0
		for j := 0; j < nbq; j++ {
			mask := 1 << uint(j)
			if bs.Get(i+j) == 1 {
				childIndex |= mask
			}
		}
		node = node.children[childIndex]
	}
	return node, nil
}

// Insert a Z/Zp integer into the prefix tree
func (t *MemPrefixTree) Insert(z *Zp) error {
	bs := NewZpBitstring(z)
	marray, err := AddElementArray(t, z)
	if err != nil {
		return err
	}
	return t.root.insert(z, marray, bs, 0)
}

// Remove a Z/Zp integer from the prefix tree
func (t *MemPrefixTree) Remove(z *Zp) error {
	bs := NewZpBitstring(z)
	return t.root.remove(z, DelElementArray(t, z), bs, 0)
}

type MemPrefixNode struct {
	// All nodes share the tree definition as a common context
	*MemPrefixTree
	// Parent of this node. Root's parent == nil
	parent *MemPrefixNode
	// Key in parent's children collection (0..(1<<bitquantum))
	key int
	// Child nodes, indexed by bitstring counting order
	// Each node will have 2**bitquantum children when leaf == false
	children []*MemPrefixNode
	// Zp elements stored at this node, if it's a leaf node
	elements []*Zp
	// Number of total elements at or below this node
	numElements int
	// Sample values at this node
	svalues []*Zp
}

func (n *MemPrefixNode) Parent() (PrefixNode, bool) { return n.parent, n.parent != nil }

func (n *MemPrefixNode) Key() *Bitstring {
	var keys []int
	for cur := n; cur != nil && cur.parent != nil; cur = cur.parent {
		keys = append([]int{cur.key}, keys...)
	}
	bs := NewBitstring(len(keys) * n.BitQuantum())
	for i := len(keys) - 1; i >= 0; i-- {
		for j := 0; j < n.BitQuantum(); j++ {
			if ((keys[i] >> uint(j)) & 0x01) == 1 {
				bs.Set(i*n.BitQuantum() + j)
			} else {
				bs.Unset(i*n.BitQuantum() + j)
			}
		}
	}
	return bs
}

func (n *MemPrefixNode) Children() (result []PrefixNode) {
	for _, child := range n.children {
		result = append(result, child)
	}
	return
}

func (n *MemPrefixNode) Elements() []*Zp {
	if n.IsLeaf() {
		return n.elements
	}
	var result []*Zp
	for _, child := range n.children {
		result = append(result, child.Elements()...)
	}
	return result
}

func (n *MemPrefixNode) Size() int      { return n.numElements }
func (n *MemPrefixNode) SValues() []*Zp { return n.svalues }

func (n *MemPrefixNode) init(t *MemPrefixTree) {
	n.MemPrefixTree = t
	n.svalues = make([]*Zp, t.NumSamples())
	for i := 0; i < len(n.svalues); i++ {
		n.svalues[i] = Zi(P_SKS, 1)
	}
}

func (n *MemPrefixNode) IsLeaf() bool {
	return len(n.children) == 0
}

func (n *MemPrefixNode) insert(z *Zp, marray []*Zp, bs *Bitstring, depth int) error {
	n.updateSvalues(z, marray)
	n.numElements++
	if n.IsLeaf() {
		if len(n.elements) > n.SplitThreshold() {
			err := n.split(depth)
			if err != nil {
				return err
			}
		} else {
			for _, nz := range n.elements {
				if nz.Cmp(z) == 0 {
					panic("Duplicate: " + z.String())
				}
			}
			n.elements = append(n.elements, z)
			return nil
		}
	}
	childIndex := NextChild(n, bs, depth)
	child := n.Children()[childIndex].(*MemPrefixNode)
	return child.insert(z, marray, bs, depth+1)
}

func (n *MemPrefixNode) split(depth int) error {
	// Create child nodes
	numChildren := 1 << uint(n.BitQuantum())
	for i := 0; i < numChildren; i++ {
		child := &MemPrefixNode{parent: n}
		child.key = i
		child.init(n.MemPrefixTree)
		n.children = append(n.children, child)
	}
	// Move elements into child nodes
	for _, element := range n.elements {
		bs := NewZpBitstring(element)
		childIndex := NextChild(n, bs, depth)
		child := n.children[childIndex]
		marray, err := AddElementArray(n.MemPrefixTree, element)
		if err != nil {
			return err
		}
		err = child.insert(element, marray, bs, depth+1)
		if err != nil {
			return err
		}
	}
	n.elements = nil
	return nil
}

func NextChild(n PrefixNode, bs *Bitstring, depth int) int {
	if n.IsLeaf() {
		panic("Cannot dereference child of leaf node")
	}
	childIndex := 0
	nbq := n.BitQuantum()
	for i := 0; i < nbq; i++ {
		mask := 1 << uint(i)
		if bs.Get(depth*nbq+i) == 1 {
			childIndex |= mask
		}
	}
	return childIndex
}

func (n *MemPrefixNode) updateSvalues(z *Zp, marray []*Zp) {
	if len(marray) != len(n.points) {
		panic("Inconsistent NumSamples size")
	}
	for i := 0; i < len(marray); i++ {
		n.svalues[i] = Z(z.P).Mul(n.svalues[i], marray[i])
	}
}

func (n *MemPrefixNode) remove(z *Zp, marray []*Zp, bs *Bitstring, depth int) error {
	n.updateSvalues(z, marray)
	n.numElements--
	if !n.IsLeaf() {
		if n.numElements <= n.JoinThreshold() {
			n.join()
		} else {
			childIndex := NextChild(n, bs, depth)
			child := n.Children()[childIndex].(*MemPrefixNode)
			return child.remove(z, marray, bs, depth+1)
		}
	}
	n.elements = withRemoved(n.elements, z)
	return nil
}

func (n *MemPrefixNode) join() {
	var childNode *MemPrefixNode
	for len(n.children) > 0 {
		childNode, n.children = n.children[0], n.children[1:]
		n.elements = append(n.elements, childNode.elements...)
		n.children = append(n.children, childNode.children...)
		childNode.children = nil
	}
	n.children = nil
}

func withRemoved(elements []*Zp, z *Zp) (result []*Zp) {
	var has bool
	for _, element := range elements {
		if element.Cmp(z) != 0 {
			result = append(result, element)
		} else {
			has = true
		}
	}
	if !has {
		panic("Remove non-existent element from node")
	}
	return
}
