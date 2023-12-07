# Read Me

## Model Overview
This model is used to simulate penetration testing (pentesting) on a home network that has multiple IoT devices connected. There is a classic model as well as a temporal model. The domain files for each model can be found in their respective folder. 

## Assumptions
(-) Attacker can only perform one attack at a time.

(-) All devices begin disconnected from network.
 

## Types
Types are used to describe the network, the devices and their individual makeup. This refers to hardwear, password protection, whether the device encrypts, etc. 

## Predicates
Similar to types, predicates are used to define the configuration of the network and devices as well as how they are interconnected. It also includes a "compromised" which indicates an attacker has gained control of a certain device. 

## Actions
Actions are mostly used to capture the actions an attacker may use to compromise a network. All the actions are based on documented attacks by researchers. Additionnally, actions are also included to allow an attacker to cause trigger events which causes devices to connect to the network. This isn't necessarily realistic, since it is likely the trigger events are out of the control of the attacker. However, we can assume "the worst case scenario" that luck is in the favaour of the attacker. 

## Functions
Functions are used to add restraints that will be set by the IFTAT protocol. 
### Trigger Count
This tracks home many times a trigger event has occured for a respective device.
### Max Trigger Count
This stipulates a maximum number of times an attacker can trigger for a respective device. 
### Trigger Length
This is the time that the device will be allowed online during a trigger event. (as stipulated by the IFTAT prtocol)

## Initial & Goal State
### Initial State
The initial state is used to set the configuration of the network and each device. It also sets the IFTAT limitations. One device begins as compromised as a starting point for the attacker.
### Goal State 
The goal of the planner is to compromise specific devices. 

## Setting up experiments
### generate_problem.py 
This file is used to generate problem files for a scenario of which device x is compromised and there are x amount of vulnerabilities present in the remaining devices. Lines 13 and 14 are the only ones that need to be changed. This is where you choose which device is compromised and how many devices should be vulnerable. The vulnerable devices are chosen randomly. The classical and temporal problem files will be generated in the problem_files folder of the respective classic and temporal folder. 

compromised device should be varied from 1 -> 9 while also varying number of vulnerabilities 1->8 for each device

### gen_problem_multiple_comp.py
This file is used to generate problem files for the scenario of multiple devices initially being compromised and it trying to compromised all the other devices. Lines 29 and 31 are the only ones that need to be changed. Each vulnerable device will have a respective problem file where they are the only device with a vulnerability and the goal will be initialized to infect them. The classical and temporal problem files will be generated in the problem_files folder of the respective classic and temporal folder. 

In this file, all that must be modified is num_compromised devices. Then the planner must be run on each problem file generated.



### scale_problem_files.py
This file is used to generate problem files for testing the scalability of popf and optic planners. It only creates temporal problem files. Lines 33 and 36 are the only ones that need to be changed. There is a multi_factor which determines how many machines are included in the problem file. The base is 10. So, if multi_factor = 2, total machines = 20. Additionally, it maintains a specific distribution of individual devices. Lastly, you can modify how many vulnerabilities are included as well. 

## Problem Files
A problem file must be made for each vulnerability. This is because the goal state can't maximize the number of vulnerabilities it finds and if it can't accomplish 1 of the goal states (one vulnerable), the planner will not be able to formulate a plan even if it may exploit other vulnerabilities.

## Commands
### Classic Command
lama-first <domain_file> <problem_file>
### Temporal 
popf <domain_file> <problem_file>

or 

optic <domain_file> <problem_file>






