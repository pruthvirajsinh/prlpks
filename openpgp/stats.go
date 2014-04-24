/*
PRLPKS - OpenPGP Synchronized Key Server with Deletion
Copyright (c) 2014 Pruthvirajsinh Rajendrasinh Chauhan

PRLPKS is based heavily on hockeypuck(https://launchpad.net/hockeypuck) by Casey Marshall, copyright 2013(GNU GPL v3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package openpgp

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/pruthvirajsinh/prlpks/hkp"
)

func (w *Worker) Stats(l *hkp.Lookup) {
	resp := &StatsResponse{Lookup: l, Stats: &HkpStats{Worker: w}}
	resp.Stats.fetchServerInfo(l)
	err := resp.Stats.fetchKeyStats()
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	err = resp.Stats.fetchTotalKeys()
	if err != nil {
		l.Response() <- &ErrorResponse{err}
		return
	}
	l.Response() <- resp
}

type PksKeyStats struct {
	Timestamp time.Time `db:"start"`
	Created   int       `db:"created"`
	Modified  int       `db:"modified"`
}

func (s *PksKeyStats) Day() string {
	return s.Timestamp.Format("2006-01-02 MST")
}

func (s *PksKeyStats) Hour() string {
	return s.Timestamp.Format("2006-01-02 15:04 MST")
}

type HkpStats struct {
	*Worker
	Timestamp      time.Time
	Hostname       string
	Port           int
	Version        string
	PksPeers       []PksStatus
	TotalKeys      int `db:"total_keys"`
	KeyStatsHourly []PksKeyStats
	KeyStatsDaily  []PksKeyStats
}

func (s *HkpStats) fetchServerInfo(l *hkp.Lookup) {
	s.Timestamp = time.Now()
	if host, port, err := net.SplitHostPort(l.Host); err == nil {
		s.Hostname = host
		if s.Port, err = strconv.Atoi(port); err != nil {
			log.Println("Error parsing port:", err)
		}
	} else {
		s.Hostname = l.Host
		log.Println("Error parsing Host:", err)
	}
}

var selectHourlyStats string = `
SELECT SUM(created) AS created, SUM(modified) AS modified, hour AS start
FROM (
	SELECT COUNT(*) AS created, 0 AS modified, date_trunc('hour', ctime) AS hour
	FROM openpgp_pubkey WHERE ctime > date_trunc('day', now() - interval '1 day')
	GROUP BY hour
	UNION
	SELECT 0 AS created, COUNT(*) AS modified, date_trunc('hour', mtime) AS hour
	FROM openpgp_pubkey WHERE mtime > date_trunc('day', now() - interval '1 day')
		AND mtime > ctime GROUP BY hour) AS hourly
GROUP BY hour ORDER BY start DESC`

var selectDailyStats string = `
SELECT SUM(created) AS created, SUM(modified) AS modified, day AS start
FROM (
	SELECT COUNT(*) AS created, 0 AS modified, date_trunc('day', ctime) AS day
	FROM openpgp_pubkey WHERE ctime > date_trunc('week', now() - interval '1 week')
	GROUP BY day
	UNION
	SELECT 0 AS created, COUNT(*) AS modified, date_trunc('day', mtime) AS day
	FROM openpgp_pubkey WHERE mtime > date_trunc('week', now() - interval '1 week')
		AND mtime > ctime GROUP BY day) AS daily
GROUP BY day ORDER BY start DESC`

func (s *HkpStats) fetchKeyStats() (err error) {
	err = s.db.Select(&s.KeyStatsHourly, selectHourlyStats)
	if err != nil {
		return
	}
	err = s.db.Select(&s.KeyStatsDaily, selectDailyStats)
	return
}

func (s *HkpStats) fetchTotalKeys() (err error) {
	return s.db.Get(s, `
SELECT CAST(reltuples AS INTEGER) AS total_keys FROM pg_class WHERE relname = 'openpgp_pubkey'`)
}
