#!/usr/bin/python3
import re
from operator import itemgetter
from geoip import geolite2
from datetime import date
import os

__FILE_DATA = []
__FILE_ELEMENTS = []

#Author: Max E. Friedland (mef5530@rit.edu)
#Date: 4/3/22

#Opens the file and fills an array with each line
def readFile(fn="syslog.log"):
    f = open(fn, "r")
    for line in f:
        __FILE_DATA.append(line)

#Checks the data array for the ip and either increaces the count or creates a new entry
def addIP(ip):
    found = False
    for e in __FILE_ELEMENTS:
        if e[0] == ip:
            e[1]+=1
            found = True
    if (found == False):
        line = []
        line.append(ip)
        line.append(1)
        __FILE_ELEMENTS.append(line)

#Looks through the lines and finds the failed passwords, then uses regex to find the ip and add it to the data array
def populate():
    for line in __FILE_DATA:
        if "Failed password" in line:
            result = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line).group()
            addIP(result)

#formats and prints a report using geoip to find the locations
def printReport():
    os.system("clear")
    list = sorted(__FILE_ELEMENTS, key=itemgetter(1))
    print("Attacker Report - ", date.today())
    print("{:<10} {:<20} {:<10}".format("COUNT", "IP ADDRESS", "COUNTRY"))
    for e in list:
        if (e[1] >= 10):
            match = geolite2.lookup(e[0])
            print("{:<10} {:<20} {:<10}".format(e[1], e[0], match.country))

def main():
    readFile()
    populate()
    printReport()

main()