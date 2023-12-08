import os
import numpy as np
import random

new_file = "problem.home.pddl"
folder_name = "Temporal\problem_files"

file_name = os.path.join(folder_name,new_file)

#### Change the following to generate problem files
#########################################################################################
# compromised device
compromised_device = 1 # device number 
num_vuln = 2 # may cause bugs if set to 1 have to modify code (it works with mostly arrays)

################################################################################

# distribution of IoT devices
num_doorbells = 1
num_security_camera = 2
num_printers = 1
num_google_homes = 2
num_smart_speaker = 1
num_light_sw = 3

light_trigger_count = np.array([15,10,5])

num_devices = num_doorbells + num_security_camera + num_printers + num_google_homes + num_smart_speaker + num_light_sw
all_devices = np.repeat("security_cam0",num_devices)

device_idx = 0

# compile list of all devices
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
print("Compromised device (" + str(compromised_device) + ") " + all_devices[compromised_device] )
vuln_idx = np.zeros(num_vuln).astype(int)
duplicate = False

# randomly choose vulnerable devices 
number_pool = [num for num in range(0, num_devices-1) if num != compromised_device]
vuln_idx = random_numbers = random.sample(number_pool, num_vuln)

print("Vulnerable devices:")
print(all_devices[vuln_idx])
    
######## Trigger lengths and frequency ###########
# trigger lengths per IoT devices
doorbell_len = 1
security_camera_len = 5
printer_len = 2
google_home_len = 2
smart_speaker_len = 45
light_sw_len = 1

# number of triggers per IoT device
doorbell_trig = 1
security_camera_trig = 5
printer_trig = 2
google_home_trig = 2
smart_speaker_trig = 1
light_trigger_count = np.array([15,10,5]) # may vary switch to switch based on how common the rooms are


device_str = "\n\t\t"

new_file = "problem.home.pddl"
folder_name = "Temporal\problem_files"

file_name = os.path.join(folder_name,new_file)

## Create a problem file for each vulnerability

for j in range(num_vuln):
    file_name = os.path.join("Temporal\problem_files","promblem.home_g" + str(j) + ".pddl")
    file_name_c = os.path.join("Classic\problem_files","problem.homeC_g" + str(j)+ ".pddl")

    device_str = "\n\t\t"

    with open(file_name, 'w') as file:
    # Write content to the file
    # domain & objects
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

        # init section
        file.write("\n\n\t(:init\n\t\t(not_performing_attack)")
        file.write("\n\t\t(proceeds am6 am7)\n\t\t(proceeds am7 am8)\n\t\t(proceeds am8 am9)\n\t\t(proceeds am9 am10)\n\t\t(proceeds am10 am11)\n\t\t(proceeds am11 pm12)\n\t\t(proceeds pm12 pm1)\n\t\t(proceeds pm1 pm2)\n\t\t(proceeds pm2 pm3)\n\t\t(proceeds pm3 pm4)\n\t\t(proceeds pm4 pm5)\n\t\t(proceeds pm5 pm6)\n\t\t(proceeds pm6 pm7)\n\t\t(proceeds pm7 pm8)\n\t\t(proceeds pm8 pm9)\n\t\t(proceeds pm9 pm10)\n\t\t(proceeds pm10 pm11)\n\t\t(proceeds pm11 am6)\n\t\t(time_of_day am6)")
        file.write("\n\n\t\t; Define Network Connections")
        file.write("\n\t\t(network_hardwear n1 switch)\n")

        file.write("\n\t\t; assume all devices are disconnected")

        file.write("\n\n\t\t; doorbell initialization")
        for i in range(num_doorbells):
            file.write("\n\t\t; doorbell " + str(i))
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " am8)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " pm5)")
            file.write("\n\t\t(trigger_at_time doorbell" + str(i) + " pm6)")

            file.write("\n\t\t(not_connected_to_network doorbell" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count doorbell" + str(i) + ") " + str(doorbell_trig) + ")")
            file.write("\n\t\t(=(trigger_length doorbell" + str(i) + ") " + str(doorbell_len) + ")")
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
            file.write("\n\t\t(=(max_trigger_count security_cam" + str(i) + ") " + str(security_camera_trig) + ")")
            file.write("\n\t\t(=(trigger_length security_cam" + str(i) + ") " + str(security_camera_len) + ")")
            file.write("\n\t\t(=(trigger_count security_cam"+ str(i) + ") 0)\n")
        
        file.write("\n\n\t\t; printer initialization")
        for i in range(num_printers):
            file.write("\n\t\t; printer " + str(i))
            file.write("\n\t\t(trigger_at_time printer" + str(i) + " pm7)")
            file.write("\n\t\t(trigger_at_time printer" + str(i) + " pm6)")

            file.write("\n\n\t\t(not_connected_to_network printer" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count printer" + str(i) + ") " + str(printer_trig) + ")")
            file.write("\n\t\t(=(trigger_length printer" + str(i) + ") " + str(printer_len) + ")")
            file.write("\n\t\t(=(trigger_count printer"+ str(i) + ") 0)\n")


        file.write("\n\n\t\t; google home initialization")
        for i in range(num_google_homes):
            file.write("\n\t\t; google_home " + str(i))
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " am7)")
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " pm8)")
            file.write("\n\t\t(trigger_at_time google_home" + str(i) + " pm10)")

            file.write("\n\n\t\t(not_connected_to_network google_home" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count google_home" + str(i) + ") " + str(google_home_trig) + ")")
            file.write("\n\t\t(=(trigger_length google_home" + str(i) + ") " + str(google_home_len) + ")")
            file.write("\n\t\t(=(trigger_count google_home"+ str(i) + ") 0)\n")

        file.write("\n\n\t\t; speaker initialization")
        for i in range(num_smart_speaker):
            file.write("\n\t\t; speaker " + str(i))
            file.write("\n\t\t(trigger_at_time speaker" + str(i) + " pm8)")
            file.write("\n\n\t\t(not_connected_to_network speaker" + str(i) + " n1)")
            file.write("\n\t\t(=(max_trigger_count speaker" + str(i) + ") " + str(smart_speaker_trig) + ")")
            file.write("\n\t\t(=(trigger_length speaker" + str(i) + ") " + str(smart_speaker_len) + ")")
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
            file.write("\n\t\t(=(trigger_length light_sw" + str(i) + ") " + str(light_sw_len) + ")")
            file.write("\n\t\t(=(trigger_count light_sw"+ str(i) + ") 0)\n")

        file.write("\n\t\t;Vulnerability Initializaton\n")

        for i in range(num_vuln):
            if(("doorbell" in all_devices[vuln_idx[i]])| ("light_sw" in all_devices[vuln_idx[i]])):
                file.write("\n\t\t(does_encrypt " + all_devices[vuln_idx[i]] + ")" )
                file.write("\n\t\t(open_TCP_23_port " + all_devices[vuln_idx[i]]  + ")" )
            if(("security_cam" in all_devices[vuln_idx[i]]) | ("speaker" in all_devices[vuln_idx[i]])):
                file.write("\n\t\t(has_pass " + all_devices[vuln_idx[i]] + " weak_password)")
            if(("printer" in all_devices[vuln_idx[i]]) |( "google_home" in all_devices[vuln_idx[i]])):
                file.write("\n\t\t(no_auth_firmwear " + all_devices[vuln_idx[i]] + ")")

        file.write("\n\n\t\t;initial compromised device")
        file.write("\n\t\t(is_compromised " + all_devices[compromised_device] + ")")
        file.write("\n\n\t)\n")


        # goal state
        file.write("\n\t(:goal (and\n")
        file.write("\n\t\t(is_compromised " + all_devices[vuln_idx[j]] + ")")
        file.write("\n\t\t(time_of_day pm11)")

        file.write("\n\t))")
        file.write("\n)")

    device_str = "\n\t\t"

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

        file_c.write("\n\t\t;Vulnerability Initializaton")
        
        for i in range(num_vuln):
            if(("doorbell" in all_devices[vuln_idx[i]])| ("light_sw" in all_devices[vuln_idx[i]])):
                file_c.write("\n\t\t(does_encrypt " + all_devices[vuln_idx[i]] + ")" )
                file_c.write("\n\t\t(open_TCP_23_port " + all_devices[vuln_idx[i]]  + ")" )
            if(("security_cam" in all_devices[vuln_idx[i]]) | ("speaker" in all_devices[vuln_idx[i]])):
                file_c.write("\n\t\t(has_pass " + all_devices[vuln_idx[i]] + " weak_password)")
            if(("printer" in all_devices[vuln_idx[i]]) |( "google_home" in all_devices[vuln_idx[i]])):
                file_c.write("\n\t\t(no_auth_firmwear " + all_devices[vuln_idx[i]] + ")")
            file_c.write("\n\t\t(is_compromised " + all_devices[compromised_device] + ")")

        file_c.write("\n\t)\n")

        file_c.write("\n\t(:goal (and")
        file_c.write("\n\t\t(is_compromised " + all_devices[vuln_idx[j]] + ")")
        file_c.write("\n\t))")
        file_c.write("\n)")
        


