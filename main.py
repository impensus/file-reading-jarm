# Version 1.4 (10th June 2022)
#
# Created by:
# Ben74239

from __future__ import print_function
from utils import ja3
from utils import jarm
from utils import salesforce_jarm
import argparse
import pickle
import glob
from prettytable import PrettyTable


def calculate_jarm(known_jarm_scan_ja3_hash_list, pcap_filepath, JarmHandler):
    Ja3Handler = ja3.PyJa3(pcap_filepath, known_jarm_scan_ja3_hash_list)
    ja3_object = Ja3Handler.main()

    if len(ja3_object) > 10:
        print(
            "Potential JA3 collision encountered as more than 10 JA3 + SPDY matching server hellos are in the PCAP. Exiting...")
        exit(1)

    with open(r'data/byte_array_of_ja3_from_jarm_scan.txt', 'wb') as fp:
        pickle.dump(ja3_object, fp)

    jarm_hash = JarmHandler.main()
    return jarm_hash


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", action="store_true", help="A CLI flag used to  to start test runner.", dest="test")
    parser.add_argument("-v", action="store_true", help="A CLI flag enable verbose logging in the test runners output.", dest="verbose")
    parser.add_argument("-f", action="store_true", help="A CLI flag to format the failed test output data into a table instead of newline format.", dest="format")
    args = parser.parse_args()

    known_jarm_scan_ja3_hash_list = []
    with open('data/ja3_jarm_scan_client_hellos', 'r') as hellos_file:
        known_jarm_scan_ja3_hash_list = hellos_file.read().splitlines()
    JarmHandler = jarm.PyJarm()


    if (args.test == True):
        print("")
        print("   ----------------------------- Starting Test Runner -----------------------------")
        print("")
        # Read in all pcap files in pcaps directory
        test_data = glob.glob("utils/pcaps/*.pcapng")

        failed_tests = {}
        for filepath in test_data:
            print(" [] - Currently testing: " + filepath)
            print("")


            ip = str(filepath.strip("utils/pcaps/").strip(".trace.pcapng"))
            SalesforceJarmHandler = salesforce_jarm.SalesforceJarm(ip)

            salesforce_jarm_hash = SalesforceJarmHandler.main(ip)
            our_jarm_hash = calculate_jarm(known_jarm_scan_ja3_hash_list ,filepath, JarmHandler)

            if(args.verbose):
                print("      - Salesforce Jarm: " +salesforce_jarm_hash)
                print("      -    Scripts Jarm: " +our_jarm_hash)
                print("")
                print("")


            if salesforce_jarm_hash != our_jarm_hash:
                failed_tests[salesforce_jarm_hash] = our_jarm_hash +":" + ip

        if bool(failed_tests) == True:
            print("")
            print("")
            print(" -------------------------------------------------------------------------------")
            print(" [] - - - - Warning: Some of the tests have failed.")
            print(" -------------------------------------------------------------------------------")
            print("")
            print("")

            pretty_table = PrettyTable(['Salesforce JARM', 'Script JARM', 'Site IP'])
            for key in failed_tests:
                salesforce_jarm_hash = key
                our_jarm_hash_with_ip = failed_tests[key]
                our_jarm_hash, ip = our_jarm_hash_with_ip.split(":")
                pretty_table.add_row([salesforce_jarm_hash, our_jarm_hash, ip])

                if(not args.format):
                    print("      - Non-matching JARM in test data for IP: " + str(ip))
                    print("      - Please check this instance manually.")
                    print("      - It may be that the salesforce script was unable to access the site.")
                    print("")
                    print("      -------------- Relevant data --------------")
                    print("             Sites IP: " + ip)
                    print("      Salesforce Jarm: " + salesforce_jarm_hash)
                    print("         Scripts Jarm: " + our_jarm_hash)
                    print("")
                    print("")

            if(args.format):
                print(pretty_table)

        else:
            print("")
            print("")
            print(" -------------------------------------------------------------------------------")
            print(" [] - - - - Success: All tests have passed without issue!")
            print(" -------------------------------------------------------------------------------")
            print("")
            print("")

        # Run salesforce_jarm on them and get jarm
        # Run my jarm and compare values on jarms
        # Add any differences to array and flag to user

    else:
        filepath = input("Please input the filepath of your pcap file: ")
        calculate_jarm(known_jarm_scan_ja3_hash_list, filepath, JarmHandler)



