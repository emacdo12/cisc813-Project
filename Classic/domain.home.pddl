;Header and description

(define (domain home_network)

    ;remove requirements that are not needed
    (:requirements  :equality :negative-preconditions :typing :adl)

    (:types ;todo: enumerate types and their hierarchy here, e.g. car truck bus - vehicle
        device - object
        op_sys - object
        password - object
        network - object
        net_hardwear - object
    )

    ; un-comment following line if constants are needed
    (:constants 
        weak_password strong_password - password
        Windows Linux - op_sys
        switch hub - net_hardwear
    )

    (:predicates ;todo: define predicates here
    (has_pass ?dev - device ?pass - password)
    (is_connected_to_network ?dev - device ?n - network)
    (has_os ?dev - device ?os - op_sys)
    (is_connected ?dev1 ?dev2 - device)
    (is_compromised ?dev - device)
    (network_hardwear ?n - network ?hw - net_hardwear)
    (is_sniffing ?dev1 ?dev2 - device)
    (no_auth_firmwear ?dev - device)
    (open_TCP_23_port ?dev - device)
    (does_encryption ?dev - device)
    (done_DDoS)
    )

    ; dictionary attack
    (:action dictionary_attack
        :parameters (?dev1 ?dev2 - device)
        :precondition (and 
            (is_compromised ?dev1)
            (is_connected ?dev1 ?dev2)
            (has_pass ?dev2 weak_password)
        )
        :effect (and 
            (is_compromised ?dev2)
        )
    )

    ; distributed denial of service attack
    (:action perform_DDoS_attack
        :parameters (?dev1 ?dev2 - device)
        :precondition (and 
            (is_compromised ?dev1)
            (is_compromised ?dev2)
        )
        :effect (and 
            (done_DDoS)
        )
    )

    ; man in the middle attack
    (:action arp_spoofing
        :parameters (?dev - device ?n - network )
        :precondition (and 
            (is_compromised ?dev) 
            (is_connected_to_network ?dev ?n)
        )
        :effect (and 
            (forall (?d - device)( ; all devices on network route through this device
                when (is_connected_to_network ?d ?n)
                    (and(is_connected ?dev ?d)(is_sniffing ?dev ?d))
            )  
            )
        )
    )

    ; man in the middle attack
    (:action port_stealing
        :parameters (?dev - device ?n - network)
        :precondition (and 
            (network_hardwear ?n switch)
            (is_connected_to_network ?dev ?n)
            (is_compromised ?dev)
        )
        :effect (and 
            (forall (?d - device)( ; all devices on network route through this device
                when (is_connected_to_network ?d ?n)
                    (and(is_connected ?dev ?d)(is_sniffing ?dev ?d))
            ) 
            )
        )
    )

    (:action RFU_attack 
        :parameters (?dev1 ?dev2 - device)
        :precondition (and
            (is_compromised ?dev1)
            (is_connected ?dev1 ?dev2)
            (no_auth_firmwear ?dev2)
        )
        :effect (and
            (is_compromised ?dev2)
        )
    )

    (:action break_encrypted_keys
        :parameters (?dev1 ?dev2 - device)
        :precondition (and 
            (is_compromised ?dev1)
            (is_sniffing ?dev1 ?dev2)
            (does_encryption ?dev2)
        )
        :effect (and 
            (not(does_encryption ?dev2))
        )
    )
    

    (:action port_attack
        :parameters (?dev1 ?dev2 - device)
        :precondition (and 
            (is_sniffing ?dev1 ?dev2)
            (is_compromised ?dev1)
            (open_TCP_23_port ?dev2)
            (not(does_encryption ?dev2))
        )
        :effect (and 
            (is_compromised ?dev2)
        )
    )
)
