echo "<< Copying to build >>"
mv -f build ../
rm -fr ../build/src/github.com/pruthvirajsinh/prlpks
mkdir -p ../build/src/github.com/pruthvirajsinh/prlpks
cp -fr ../prlpks ../build/src/github.com/pruthvirajsinh/
mv -f ../build ./
echo "<< Copied to build >>"

echo "<< Compiling prlpks >>"
make build
echo "<< Compilation Finished >>"

echo "<< Copying www and configs >>"
cp -fr instroot/var/lib/prlpks/www build/bin/ 
cp -f instroot/etc/prlpks/* build/bin/

echo "<< Copied. >>"

echo "The binary and config files are in `pwd`/build/bin . You can copy the whole bin folder to the folder where you want to install the server."
echo "Setup and Configuration Steps:"
echo "1. Create a postgresql database using following command: psql -c \"create database <dbname>;\" postgres" 
echo "You can use any other command also. Goal is to create a psql database." 
echo "2. Set the the dbname and other credentials in prlpks.conf (config file)"
echo "3. Set smtp,imap and other configurations in prlpks.conf file (config file is self explanatory)"
echo "4. To explicitly allow emails edit the explicitAuth.json file"
echo "For debugging use log file (path set in config file,default is in the same directory as the binary)"
echo "To run go to bin folder or wherever you copied the contents of bin and then run command \"./prlpks run --config ./prlpks.conf\""

