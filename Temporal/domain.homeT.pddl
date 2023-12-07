(define (domain home_network_T)
    (:requirements
        :durative-actions
        :timed-initial-literals
        :typing
        :conditional-effects
        :negative-preconditions
        :duration-inequalities
        :equality
        :fluents
    )

    (:types
        device - object
        op_sys - object
        password - object
        network - object
        net_hardwear - object
        t - object
    )

    (:constants
        weak_password strong_password - password
        Windows Linux - op_sys
        switch hub - net_hardwear
        am6 am7 am8 am9 am10 am11 pm12 pm1 pm2 pm3 pm4 pm5 pm6 pm7 pm8 pm9 pm10 pm11 - t
    )

    (:predicates
        (has_pass ?dev - device ?pass - password)
        (not_connected_to_network ?dev - device ?n - network)
        (is_connected_to_network ?dev - device ?n - network)
        (is_connected ?dev1 ?dev2 - device)
        (not_connected ?dev1 ?dev2 - device)
        (is_compromised ?dev - device)
        (network_hardwear ?n - network ?hw - net_hardwear)
        (is_sniffing ?dev1 ?dev2 - device)
        (no_auth_firmwear ?dev - device)
        (open_TCP_23_port ?dev - device)
        (does_encrypt ?dev - device)
        (does_not_encrypt ?dev - device)
        (done_DDoS)
        (not_performing_attack)
        (has_addresses_of_other_devices ?dev - device)
        (time_of_day ?t - t)
        (proceeds ?t1 ?t2 - t)
        (trigger_at_time ?dev - device ?tim - t)
    )

    (:functions
        (trigger_count ?dev - device) ; number of times a trigger event has occured
        (max_trigger_count ?dev - device) ; number of times a trigger can occur for specific device
        (trigger_length ?dev - device) ; length of time device is connected to the internet
    )

    ; progress time from hour to hour
    (:durative-action progress_time
        :parameters (?t1 ?t2 - t)
        :duration (= ?duration 60)
        :condition (and 
            (at start (proceeds ?t1 ?t2))
            (at start (time_of_day ?t1))
        )
        :effect (and 
            (at start (time_of_day ?t2))
            (at end (time_of_day ?t2))
            
        )
    )
    



    ; Attacks

    (:durative-action arp_spoofing
    :parameters (?dev - device ?n - network)
    :duration (= ?duration 0.5)
    :condition (and 
            (at start(is_compromised ?dev))
            (over all(is_connected_to_network ?dev ?n))
        )
        :effect (and 
            (at end (has_addresses_of_other_devices ?dev))
        )
    )

    ; attack that allows attacker to gain access to other devices 

    (:durative-action port_stealing
        :parameters (?dev - device ?n - network)
        :duration (= ?duration 0.5)
        :condition(and
            (at start (network_hardwear ?n switch))
            (over all (is_connected_to_network ?dev ?n))
        )
        :effect (and 
            (at end (has_addresses_of_other_devices ?dev))
        )
    )

    ; manipulate devices with lack of flowers 
    (:durative-action RFU_attack
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 1)
        :condition (and 
            (at start (is_compromised ?dev1))
            (at start (no_auth_firmwear ?dev2))
            (at start (not_performing_attack))
            (at start (is_connected ?dev1 ?dev2))
            (over all (is_connected_to_network ?dev1 ?n))
            (over all (is_connected_to_network ?dev2 ?n))
        )
        :effect (and 
            (at start (not(not_performing_attack)))
            (at end (not_performing_attack))
            (at end (is_compromised ?dev2))
        )
    )


    (:durative-action perform_DDos_attack
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 15)
        :condition (and 
            (at start (and 
                (is_compromised ?dev1)
                (is_compromised ?dev2)
            ))
            (over all (and 
                (is_connected_to_network ?dev1 ?n)
                (is_connected_to_network ?dev2 ?n)
            ))
        )
        :effect (and 
            (at start (not(not_performing_attack)))
            (at end (not_performing_attack))
            (at end (done_DDoS))
        )
    )

    ; guess users password with dictionary attack
    (:durative-action dictionary_attack
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 5) ; can take 5 mins, assuming weak passwords or default passwords
        :condition (and 
            (at start (and
                (is_compromised ?dev1)
                (has_pass ?dev2 weak_password)
                (is_connected ?dev1 ?dev2)
            ))
            (over all (and 
                (is_connected_to_network ?dev2 ?n)
                (is_connected_to_network ?dev1 ?n)
            ))
        )
        :effect (and 
            (at start (not(not_performing_attack)))
            (at end (not_performing_attack))
            (at end(is_compromised ?dev2))
        )
    )

    ; If someone is privy to a connection, they can potentially break encryption
    (:durative-action break_encrypted_keys
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 5)
        :condition (and 
            (at start (is_compromised ?dev1))
            (at start (is_sniffing ?dev1 ?dev2))
            (at start (does_encrypt ?dev2))
            (over all (is_connected_to_network ?dev1 ?n))
            (over all (is_connected_to_network ?dev2 ?n))
        )
        :effect (and 
            (at end (not(does_encrypt ?dev2)))
            (at end (does_not_encrypt ?dev2))
        )
    )

    ; Take advantage of open 23 port
    (:durative-action port_attack
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 2)
        :condition(and
            (at start (is_sniffing ?dev1 ?dev2))
            (at start (is_compromised ?dev1))
            (at start (open_TCP_23_port ?dev2))
            (at start (does_not_encrypt ?dev2))
            (at start (is_connected ?dev1 ?dev2))
            (over all (is_connected_to_network ?dev1 ?n))
            (over all (is_connected_to_network ?dev2 ?n))
        )
        :effect (and 
            (at end (is_compromised ?dev2))
            (at start (not(not_performing_attack)))
            (at end (not_performing_attack))
        )
    
    )

    ; Action to connect compromised device to another & sniff with compromised device

    (:durative-action connecting_indiv_devices
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 1)
        :condition (and 
            (at start (is_connected_to_network ?dev1 ?n))
            (at start (is_connected_to_network ?dev2 ?n))
            (at start (has_addresses_of_other_devices ?dev1))
        )
        :effect (and 
            (at end (is_connected ?dev1 ?dev2))
            
        )
    )

    (:durative-action sniffing_indiv_devices
        :parameters (?dev1 ?dev2 - device ?n - network)
        :duration (= ?duration 1)
        :condition (and 
            (at start (is_connected_to_network ?dev1 ?n))
            (at start (is_connected_to_network ?dev2 ?n))
            (at start (has_addresses_of_other_devices ?dev1))
        )
        :effect (and 
            (at end (is_sniffing ?dev1 ?dev2))
            
        )
    )
    

    ; Action to bring device online

    (:durative-action trigger_event
        :parameters (?dev - device ?n - network ?tim - t)
        :duration (= ?duration (trigger_length ?dev))
        :condition (and 
            (at start (not_connected_to_network ?dev ?n))
            (at start (<=(trigger_count ?dev)(max_trigger_count ?dev)))
            (at start (trigger_at_time ?dev ?tim))
            (at start (time_of_day ?tim))
        )
        :effect (and
            (at start (increase (trigger_count ?dev) 1))
            (at start (is_connected_to_network ?dev ?n))
            (at start(not(not_connected_to_network ?dev ?n)))
            (at end(not(is_connected_to_network ?dev ?n)))
            (at end (not_connected_to_network ?dev ?n))
            
        )
    )

    
)