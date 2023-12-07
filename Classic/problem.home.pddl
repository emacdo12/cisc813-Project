(define (problem pentesting) 
(:domain home_network)
(:objects 
    d1 d2 d3 d4 d5 - device
    n1 - network
)

(:init
    ; network def and connections
    (network_hardwear n1 switch)
    (is_connected_to_network d1 n1)
    (is_connected_to_network d2 n1)
    (is_connected_to_network d3 n1)
    (is_connected_to_network d4 n1)
    (is_connected_to_network d5 n1)

    ; d1 def
    (is_compromised d1)

    ; d2 def
    (has_pass d2 weak_password)

    ; d3 def
    (has_pass d3 strong_password)

    ; d4 def
    (does_encryption d4)
    (open_TCP_23_port d4)

    ; d5 def
    (no_auth_firmwear d5)
    
)

(:goal (and
    (is_compromised d2)
    (is_compromised d4)
    (is_compromised d5)
    (done_DDoS)
))
)
