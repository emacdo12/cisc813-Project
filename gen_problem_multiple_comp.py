import os
import numpy as np
import random

##### Constants ################
################################
# trigger lengths per IoT devices
DOORBELL_LEN = 1
SECURITY_CAMERA_LEN = 5
PRINTER_LEN = 2
GOOGLE_HOME_LEN = 2
SMART_SPEAKER_LEN = 45
LIGHT_SW_LEN = 1

# number of triggers per IoT device
DOORBELL_TRIG= 1
SECURITY_CAMERA_TRIG = 5
PRINTER_TRIG = 2
GOOGLE_HOME_TRIG = 2
SMART_SPEAKER_TRIG = 1



# This file is for generating problem files for the scenario where there are multiple devices intitially compromised.

#### Change the following to generate problem files
#########################################################################################
# compromised device
num_compromised_device = 8
# number of vulnerable devices (the rest)
num_vuln = 10 - num_compromised_device

# distribution of IoT devices 
multi_factor = 1
num_doorbells = 1 * multi_factor
num_security_camera = 2 * multi_factor
num_printers = 1 * multi_factor
num_google_homes = 2 * multi_factor
num_smart_speaker = 1 * multi_factor
num_light_sw = 3 * multi_factor

light_trigger_count = np.array([15,10,5]) # differnt rooms have different frequency of use

################################################################################

num_devices = num_doorbells + num_security_camera + num_printers + num_google_homes + num_smart_speaker + num_light_sw
all_devices = np.repeat("security_cam0",num_devices)

# Compile list of all the devices
device_idx = 0
for i in range(num_doorbells):
    all_devices[device_idx] = "doorbell" + str(i)
    device_idx = device_idx + 1
    
for i in range(num_security_camera):
    all_devices[device_idx] = "security_cam" + str(i)
    device_idx = device_idx + 1
    
for i in range(num_printers):
    all_devices[device_idx] = "printer" + str(i)
    device_idx = device_idx + 1
    
for i in range(num_google_homes):
    all_devices[device_idx] = "google_home" + str(i)
    device_idx = device_idx + 1

for i in range(num_smart_speaker):
    all_devices[device_idx] = "speaker" + str(i)
    device_idx = device_idx + 1

for i in range(num_light_sw):
    all_devices[device_idx] = "light_sw" + str(i)
    device_idx = device_idx + 1

print(all_devices)

# Randomly choose initial compromised machines
vuln_idx = np.zeros(num_devices).astype(int)
number_pool = [num for num in range(0, num_devices-1)]
compromised_idx = random_numbers = random.sample(number_pool, num_compromised_device)

vuln_idx[compromised_idx] = 1
comp_devices = all_devices[compromised_idx]
vuln_idx = vuln_idx == 0
vuln_devices = all_devices[vuln_idx]

print("Initially Compromised Devices:")
print(comp_devices)
print("Other devices with vulnerabilities:")
print(vuln_devices)
    

device_str = "\n\t\t"


# file and path locations
new_file = "problem.home.pddl"
folder_name = "Temporal\problem_files"

file_name = os.path.join(folder_name,new_file)

for j in range(num_vuln): # generate a new problem file for each vulnerability
    file_name = os.path.join("Temporal\problem_files","promblem.home_g" + str(j) + ".pddl")
    file_name_c = os.path.join("Classic\problem_files","problem.homeC_g" + str(j)+ ".pddl")

    device_str = "\n\t\t"

    with open(file_name, 'w') as file:
    # Write content to the file
    ################## domain & objects ######################################
        file.write("(define (problem pentesting)\n\t(:domain home_network_T)\n\t(:objects")
        for i in range(num_doorbells):
            device_str = device_str + " doorbell" + str(i)  
        for i in range(num_security_camera):
            device_str = device_str + " security_cam" + str(i)
        for i in range(num_printers):
            device_str = device_str + " printer" + str(i)
        for i in range(num_google_homes):
            device_str = device_str + " google_home" + str(i)
        for i in range(num_smart_speaker):
            device_str = device_str + " speaker" + str(i)
        for i in range(num_light_sw):
            device_str = device_str + " light_sw" + str(i)
        device_str = device_str + " - device\n\t\t n1 - network\n\t)"
        file.write(device_str)


        ################## init section###################################
        # defining constants
        file.write("\n\n\t(:init\n\t\t(not_performing_attack)")
        file.write("\n\t\t(proceeds am6 am7)\n\t\t(proceeds am7 am8)\n\t\t(proceeds am8 am9)\n\t\t(proceeds am9 am10)\n\t\t(proceeds am10 am11)\n\t\t(proceeds am11 pm12)\n\t\t(proceeds pm12 pm1)\n\t\t(proceeds pm1 pm2)\n\t\t(proceeds pm2 pm3)\n\t\t(proceeds pm3 pm4)\n\t\t(proceeds pm4 pm5)\n\t\t(proceeds pm5 pm6)\n\t\t(proceeds pm6 pm7)\n\t\t(proceeds pm7 pm8)\n\t\t(proceeds pm8 pm9)\n\t\t(proceeds pm9 pm10)\n\t\t(proceeds pm10 pm11)\n\t\t(proceeds pm11 am6)\n\t\t(time_of_day am6)")
        file.write("\n\n\t\t; Define Network Connections")
        file.write("\n\t\t(network_hardwear n1 switch)\n")

        file.write("\n\t\t; assume all devices are disconnected")

        ## Initialize all the objects, different types have unique characteristics
        file.write("\n\n\t\t; doorbell initialization")
        for i in range(num_doorbells):
            file.write("\n\t\t; doorbell " + str(i))
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " am8)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " pm5)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " pm6)")

            file.write("\n\t\t(not_connected_to_network doorbell" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count doorbell" + str(i) + ") " + str(DOORBELL_TRIG) + ")")
            file.write("\n\t\t(=(trigger_length doorbell" + str(i) + ") " + str(DOORBELL_LEN) + ")")
            file.write("\n\t\t(=(trigger_count doorbell"+ str(i) + ") 0)\n\n")

        
        file.write("\n\n\t\t; security camera initialization")
        for i in range(num_security_camera):
            file.write("\n\t\t; security_cam " + str(i))
            file.write("\n\t\t(trigger_at_time security_cam" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time security_cam" + str(i) + " am8)")
            file.write("\n\t\t(trigger_at_time security_cam" + str(i) + " pm12)")
            file.write("\n\t\t(trigger_at_time security_cam" + str(i) + " pm5)")
            file.write("\n\t\t(trigger_at_time security_cam" + str(i) + " pm6)")

            file.write("\n\n\t\t(not_connected_to_network security_cam" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count security_cam" + str(i) + ") " + str(SECURITY_CAMERA_TRIG) + ")")
            file.write("\n\t\t(=(trigger_length security_cam" + str(i) + ") " + str(SECURITY_CAMERA_LEN) + ")")
            file.write("\n\t\t(=(trigger_count security_cam"+ str(i) + ") 0)\n")
        
        file.write("\n\n\t\t; printer initialization")
        for i in range(num_printers):
            file.write("\n\t\t; printer " + str(i))
            file.write("\n\t\t(trigger_at_time printer" + str(i) + " pm7)")
            file.write("\n\t\t(trigger_at_time printer" + str(i) + " pm6)")

            file.write("\n\n\t\t(not_connected_to_network printer" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count printer" + str(i) + ") " + str(PRINTER_TRIG) + ")")
            file.write("\n\t\t(=(trigger_length printer" + str(i) + ") " + str(PRINTER_LEN) + ")")
            file.write("\n\t\t(=(trigger_count printer"+ str(i) + ") 0)\n")


        file.write("\n\n\t\t; google home initialization")
        for i in range(num_google_homes):
            file.write("\n\t\t; google_home " + str(i))
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " pm8)")
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " pm10)")

            file.write("\n\n\t\t(not_connected_to_network google_home" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count google_home" + str(i) + ") " + str(GOOGLE_HOME_TRIG) + ")")
            file.write("\n\t\t(=(trigger_length google_home" + str(i) + ") " + str(GOOGLE_HOME_LEN) + ")")
            file.write("\n\t\t(=(trigger_count google_home"+ str(i) + ") 0)\n")

        file.write("\n\n\t\t; speaker initialization")
        for i in range(num_smart_speaker):
            file.write("\n\t\t; speaker " + str(i))
            file.write("\n\t\t(trigger_at_time speaker" + str(i) + " pm8)")
            file.write("\n\n\t\t(not_connected_to_network speaker" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count speaker" + str(i) + ") " + str(SMART_SPEAKER_TRIG) + ")")
            file.write("\n\t\t(=(trigger_length speaker" + str(i) + ") " + str(SMART_SPEAKER_LEN) + ")")
            file.write("\n\t\t(=(trigger_count speaker"+ str(i) + ") 0)\n")
        
        file.write("\n\n\t\t; light switch initialization")
        for i in range(num_light_sw):
            file.write("\n\t\t; light switch " + str(i))
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " am6)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " am8)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm12)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm1)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm2)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm5)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm6)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm7)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm8)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm9)")
            file.write("\n\t\t(trigger_at_time light_sw" + str(i) + " pm10)\n")

            file.write("\n\n\t\t(not_connected_to_network light_sw" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count light_sw" + str(i) + ") " + str(light_trigger_count[i]) + ")")
            file.write("\n\t\t(=(trigger_length light_sw" + str(i) + ") " + str(LIGHT_SW_LEN) + ")")
            file.write("\n\t\t(=(trigger_count light_sw"+ str(i) + ") 0)\n")

        file.write("\n\t\t;Vulnerability Initializaton\n")

        
        # Gives each device a vulnerability according to their type and if they've been selected
        if(("doorbell" in vuln_devices[j]) | ("light_sw" in vuln_devices[j])):
            file.write("\n\t\t(does_encrypt " + vuln_devices[j] + ")" )
            file.write("\n\t\t(open_TCP_23_port " + vuln_devices[j]  + ")" )
        if(("security_cam" in vuln_devices[j]) | ("speaker" in vuln_devices[j])):
            file.write("\n\t\t(has_pass " + vuln_devices[j] + " weak_password)")
        if(("printer" in vuln_devices[j]) |( "google_home" in vuln_devices[j])):
            file.write("\n\t\t(no_auth_firmwear " + vuln_devices[j] + ")")

        # for i, device in enumerate(vuln_devices):
        #     if(("doorbell" in device) | ("light_sw" in device)):
        #         file.write("\n\t\t(does_encrypt " + device + ")" )
        #         file.write("\n\t\t(open_TCP_23_port " + device  + ")" )
        #     if(("security_cam" in device) | ("speaker" in device)):
        #         file.write("\n\t\t(has_pass " + device + " weak_password)")
        #     if(("printer" in device) |( "google_home" in device)):
        #         file.write("\n\t\t(no_auth_firmwear " + device + ")")

        # Designates the initial compromised devices
        file.write("\n\n\t\t;initial compromised device")
        for i, device in enumerate(comp_devices):
            file.write("\n\t\t(is_compromised " + device + ")")
        
        file.write("\n\n\t)\n")


        # goal state
        file.write("\n\t(:goal (and\n")
        file.write("\n\t\t(is_compromised " + vuln_devices[j] + ")") # compromise the vulnerable device
        file.write("\n\t\t(time_of_day pm11)")

        file.write("\n\t))")
        file.write("\n)")

    device_str = "\n\t\t"

    # Same thing as before but classic model, so we don't need trigger information
    with open(file_name_c, 'w') as file_c:
        file_c.write("(define (problem pentesting)\n\t(:domain home_network)\n\t(:objects ")

        for i in range(num_doorbells):
            device_str = device_str + " doorbell" + str(i)  
        for i in range(num_security_camera):
            device_str = device_str + " security_cam" + str(i)
        for i in range(num_printers):
            device_str = device_str + " printer" + str(i)
        for i in range(num_google_homes):
            device_str = device_str + " google_home" + str(i)
        for i in range(num_smart_speaker):
            device_str = device_str + " speaker" + str(i)
        for i in range(num_light_sw):
            device_str = device_str + " light_sw" + str(i)
        
        device_str = device_str + " - device\n\t\t n1 - network\n\t)"
        file_c.write(device_str)

        file_c.write("\n\t(:init")
        file_c.write("\n\t\t(network_hardwear n1 switch)\n")

        for i in range(num_doorbells):
            file_c.write("\n\t\t(is_connected_to_network doorbell" + str(i) + " n1)")
        for i in range(num_security_camera):
            file_c.write("\n\t\t(is_connected_to_network security_cam" + str(i) + " n1)")
        for i in range(num_printers):
            file_c.write("\n\t\t(is_connected_to_network printer" + str(i) + " n1)")
        for i in range(num_google_homes):
            file_c.write("\n\t\t(is_connected_to_network google_home" + str(i) + " n1)")
        for i in range(num_smart_speaker):
            file_c.write("\n\t\t(is_connected_to_network speaker" + str(i) + " n1)")
        for i in range(num_light_sw):
            file_c.write("\n\t\t(is_connected_to_network light_sw" + str(i) + " n1)")

        file_c.write("\n\n\t\t;Vulnerability Initializaton")
        
        for i, device in enumerate(vuln_devices):
            if(("doorbell" in device)| ("light_sw" in device)):
                file_c.write("\n\t\t(does_encrypt " + device + ")" )
                file_c.write("\n\t\t(open_TCP_23_port " + device  + ")" )
            if(("security_cam" in device) | ("speaker" in device)):
                file_c.write("\n\t\t(has_pass " + device + " weak_password)")
            if(("printer" in device) |( "google_home" in device)):
                file_c.write("\n\t\t(no_auth_firmwear " + device + ")")
        
        file_c.write("\n\n\t\t;Compromised Device Initializaton")
        for i, device in enumerate(comp_devices):
            file_c.write("\n\t\t(is_compromised " + device + ")")

        file_c.write("\n\t)\n")

        file_c.write("\n\t(:goal (and")
        file_c.write("\n\t\t(is_compromised " + vuln_devices[j] + ")")
        file_c.write("\n\t))")
        file_c.write("\n)")
        


