#!/usr/bin/python
# MaskGen - Generate Password Masks
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.3
#
# Copyright (C) 2013 Peter Kacherginsky
# Copyright (C) 2015 Moloch
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.


import csv
import datetime


VERSION = "0.0.3"
LIB_VERSION = "0.0.1"


class MaskGen(object):

    def __init__(self):
        # Masks collections with meta data
        self.masks = dict()

        self.target_time = None
        self.output_file = None

        self.minlength = None
        self.maxlength = None
        self.mintime = None
        self.maxtime = None
        self.mincomplexity = None
        self.maxcomplexity = None
        self.minoccurrence = None
        self.maxoccurrence = None

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

        # Counter for total masks coverage
        self.total_occurrence = 0

    def getcomplexity(self, mask):
        """ Return mask complexity. """
        count = 1
        for char in mask[1:].split("?"):
            if char == "l":
                count *= 26
            elif char == "u":
                count *= 26
            elif char == "d":
                count *= 10
            elif char == "s":
                count *= 33
            elif char == "a":
                count *= 95
            else:
                print "[!] Error, unknown mask ?%s in a mask %s" % (char, mask)

        return count

    def loadmasks(self, filename):
        """ Load masks and apply filters. """
        maskReader = csv.reader(
            open(args[0], 'r'), delimiter=',', quotechar='"')

        for (mask, occurrence) in maskReader:

            if mask == "":
                continue

            mask_occurrence = int(occurrence)
            mask_length = len(mask) / 2
            mask_complexity = self.getcomplexity(mask)
            mask_time = mask_complexity / self.pps

            self.total_occurrence += mask_occurrence

            # Apply filters based on occurrence, length, complexity and time
            if (self.minoccurrence == None or mask_occurrence >= self.minoccurrence) and \
               (self.maxoccurrence == None or mask_occurrence <= self.maxoccurrence) and \
               (self.mincomplexity == None or mask_complexity <= self.mincomplexity) and \
               (self.maxcomplexity == None or mask_complexity <= self.maxcomplexity) and \
               (self.mintime == None or mask_time <= self.mintime) and \
               (self.maxtime == None or mask_time <= self.maxtime) and \
               (self.maxlength == None or mask_length <= self.maxlength) and \
               (self.minlength == None or mask_length >= self.minlength):

                self.masks[mask] = dict()
                self.masks[mask]['length'] = mask_length
                self.masks[mask]['occurrence'] = mask_occurrence
                self.masks[mask]['complexity'] = 1 - mask_complexity
                self.masks[mask]['time'] = mask_time
                self.masks[mask]['optindex'] = 1 - \
                    mask_complexity / mask_occurrence

    def generate_masks(self, sorting_mode):
        """
        Generate optimal password masks sorted by occurrence, complexity or
        optindex
        """
        sample_count = 0
        sample_time = 0
        sample_occurrence = 0

        # TODO Group by time here 1 minutes, 1 hour, 1 day, 1 month, 1 year....
        #      Group by length   1,2,3,4,5,6,7,8,9,10....
        #      Group by occurrence 10%, 20%, 30%, 40%, 50%....

        if self.showmasks:
            print "[L:] Mask:                          [ Occ:  ] [ Time:  ]"
        for mask in sorted(self.masks.keys(), key=lambda mask: self.masks[mask][sorting_mode], reverse=True):

            if self.showmasks:
                time_human = ">1 year" if self.masks[mask][
                    'time'] > 60 * 60 * 24 * 365 else str(datetime.timedelta(seconds=self.masks[mask]['time']))
                print "[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask, self.masks[mask]['occurrence'], time_human)

            if self.output_file:
                self.output_file.write("%s\n" % mask)

            sample_occurrence += self.masks[mask]['occurrence']
            sample_time += self.masks[mask]['time']
            sample_count += 1

            if self.target_time and sample_time > self.target_time:
                print "[!] Target time exceeded."
                break

        print "[*] Finished generating masks:"
        print "    Masks generated: %s" % sample_count
        print "    Masks coverage:  %d%% (%d/%d)" % (sample_occurrence * 100 / self.total_occurrence, sample_occurrence, self.total_occurrence)
        time_human = ">1 year" if sample_time > 60 * 60 * 24 * \
            365 else str(datetime.timedelta(seconds=sample_time))
        print "    Masks runtime:   %s" % time_human

    def getmaskscoverage(self, checkmasks):

        sample_count = 0
        sample_occurrence = 0

        total_complexity = 0

        if self.showmasks:
            print "[L:] Mask:                          [ Occ:  ] [ Time:  ]"
        for mask in checkmasks:
            mask = mask.strip()
            mask_complexity = self.getcomplexity(mask)

            total_complexity += mask_complexity

            if mask in self.masks:

                if self.showmasks:
                    time_human = ">1 year" if self.masks[mask][
                        'time'] > 60 * 60 * 24 * 365 else str(datetime.timedelta(seconds=self.masks[mask]['time']))
                    print "[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask, self.masks[mask]['occurrence'], time_human)

                if self.output_file:
                    self.output_file.write("%s\n" % mask)

                sample_occurrence += self.masks[mask]['occurrence']
                sample_count += 1

            if self.target_time and total_complexity / self.pps > self.target_time:
                print "[!] Target time exceeded."
                break

        # TODO: Something wrong here, complexity and time doesn't match with
        # estimated from policygen
        total_time = total_complexity / self.pps
        time_human = ">1 year" if total_time > 60 * 60 * 24 * \
            365 else str(datetime.timedelta(seconds=total_time))
        print "[*] Finished matching masks:"
        print "    Masks matched: %s" % sample_count
        print "    Masks coverage:  %d%% (%d/%d)" % (sample_occurrence * 100 / self.total_occurrence, sample_occurrence, self.total_occurrence)
        print "    Masks runtime:   %s" % time_human
