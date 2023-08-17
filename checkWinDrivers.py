#!/usr/bin/env python
"""
CHECKWINDRIVERS

Small script to compare vulnerabilities in a windows system, comparing the MD5 
hashes of the drivers against the database of the LOLDrivers project.
https://github.com/magicsword-io/LOLDrivers

GetDrivers:  driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Path' | ForEach-Object {$out=$_.Path+";";$out+=$(certUtil -hashFile $_.Path MD5)[1] -replace " ","";$out}
Usage:       checkWinDrivers.py drivers.log

"""

import sys
import os
import json


DB_FILE = "./db.json"


BANNER = '''
    _____ _               _  __          ___       _____       _                     
   / ____| |             | | \ \        / (_)     |  __ \     (_)                    
  | |    | |__   ___  ___| | _\ \  /\  / / _ _ __ | |  | |_ __ ___   _____ _ __ ___  
  | |    | '_ \ / _ \/ __| |/ /\ \/  \/ / | | '_ \| |  | | '__| \ \ / / _ \ '__/ __| 
  | |____| | | |  __/ (__|   <  \  /\  /  | | | | | |__| | |  | |\ V /  __/ |  \__ \ 
   \_____|_| |_|\___|\___|_|\_\  \/  \/   |_|_| |_|_____/|_|  |_| \_/ \___|_|  |___/ 
                                                                                     
 --------------------------------------------------------------------------------------

'''

def parseLog(logfile):
	f = open(logfile, 'r')
	lines = f.readlines()
	f.close()
	out={}
	for line in lines:
		file,md5=line.strip().split(";")
		out[md5]=file
	return out


def loadDB(dbFile):
	f = open(dbFile)
	data = json.load(f)
	f.close()
	return data


if __name__ == '__main__':

	found=0

	print(BANNER)

	#Check argv
	if len(sys.argv) < 2:
		print(" [!] Usage: ")
		print(" [-] To get file output")
		print("\t")
		print(" [-] To check results")
		print("\tcheckWinDrivers.py drivers.log")
		sys.exit(0)

	logfile=sys.argv[1]
	#Check log file exists
	if not os.path.exists(logfile):
		print(f" [!] {logfile} doesn't exist!")
		sys.exit(-1)

	#Load DB
	db = loadDB(DB_FILE)

	#Parse log file
	for l_md5, l_file in parseLog(logfile).items():

		#Chack matches
		if l_md5 in db.keys():
			info=db[l_md5]
			print(f" [>] {l_file}")
			print(f"\t- FILE: {info['FILE']}")
			print(f"\t- FUNC: {info['FUNC']}")
			print(f"\t- HASH: {info['HASH']}")
			print(f"\t- URL:  https://www.loldrivers.io/drivers/{info['NAME']}/")

			found+=1

	#If no founds
	if not found:
		print(" [-] No vulnerable driver found.")
		print()
