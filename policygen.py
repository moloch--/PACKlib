#!/usr/bin/python
# PolicyGen - Analyze and generate password masks according to a
#             password policy.
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.2
#
# Copyright (C) 2013 Peter Kacherginsky
# Copyright (C) 2015 Moloch
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.


import datetime
import itertools

VERSION = "0.0.2"
LIB_VERSION = "0.0.1"


class PolicyGen(object):

    def __init__(self):
        self.output_file = None

        self.minlength = 8
        self.maxlength = 8
        self.mindigit = None
        self.minlower = None
        self.minupper = None
        self.minspecial = None
        self.maxdigit = None
        self.maxlower = None
        self.maxupper = None
        self.maxspecial = None

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

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

    def generate_masks(self, noncompliant):
        """ Generate all possible password masks matching the policy """

        total_count = 0
        sample_count = 0

        # NOTE: It is better to collect total complexity
        #       not to lose precision when dividing by pps
        total_complexity = 0
        sample_complexity = 0

        # TODO: Randomize or even statistically arrange matching masks
        for length in xrange(self.minlength, self.maxlength + 1):
            print "[*] Generating %d character password masks." % length
            total_length_count = 0
            sample_length_count = 0

            total_length_complexity = 0
            sample_length_complexity = 0

            for masklist in itertools.product(['?d', '?l', '?u', '?s'],
                                              repeat=length):

                mask = ''.join(masklist)

                lowercount = 0
                uppercount = 0
                digitcount = 0
                specialcount = 0

                mask_complexity = self.getcomplexity(mask)

                total_length_count += 1
                total_length_complexity += mask_complexity

                # Count charachter types in a mask
                for char in mask[1:].split("?"):
                    if char == "l":
                        lowercount += 1
                    elif char == "u":
                        uppercount += 1
                    elif char == "d":
                        digitcount += 1
                    elif char == "s":
                        specialcount += 1

                # Filter according to password policy
                # NOTE: Perform exact opposite (XOR) operation if noncompliant
                #       flag was set when calling the function.
                if ((self.minlower == None or lowercount >= self.minlower) and
                        (self.maxlower == None or lowercount <= self.maxlower) and
                        (self.minupper == None or uppercount >= self.minupper) and
                        (self.maxupper == None or uppercount <= self.maxupper) and
                        (self.mindigit == None or digitcount >= self.mindigit) and
                        (self.maxdigit == None or digitcount <= self.maxdigit) and
                        (self.minspecial == None or specialcount >= self.minspecial) and
                        (self.maxspecial == None or specialcount <= self.maxspecial)) ^ noncompliant:

                    sample_length_count += 1
                    sample_length_complexity += mask_complexity

                    if self.showmasks:
                        mask_time = mask_complexity / self.pps
                        time_human = ">1 year" if mask_time > 60 * 60 * 24 * \
                            365 else str(datetime.timedelta(seconds=mask_time))
                        print "[{:>2}] {:<30} [l:{:>2} u:{:>2} d:{:>2} s:{:>2}] [{:>8}]  ".format(length, mask, lowercount, uppercount, digitcount, specialcount, time_human)

                    if self.output_file:
                        self.output_file.write("%s\n" % mask)

            total_count += total_length_count
            sample_count += sample_length_count

            total_complexity += total_length_complexity
            sample_complexity += sample_length_complexity

        total_time = total_complexity / self.pps
        total_time_human = ">1 year" if total_time > 60 * 60 * 24 * \
            365 else str(datetime.timedelta(seconds=total_time))
        print "[*] Total Masks:  %d Time: %s" % (total_count, total_time_human)

        sample_time = sample_complexity / self.pps
        sample_time_human = ">1 year" if sample_time > 60 * 60 * \
            24 * 365 else str(datetime.timedelta(seconds=sample_time))
        print "[*] Policy Masks: %d Time: %s" % (sample_count, sample_time_human)
