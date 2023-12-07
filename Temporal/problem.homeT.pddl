(define (problem pentesting) 
    (:domain home_network_T)
    (:objects 
        d1 d2 d3 d4 d5 - device
        n1 - network
    )

    (:init
        (not_performing_attack)

        (proceeds am6 am7)
        (proceeds am7 am8)
        (proceeds am8 am9)
        (proceeds am9 am10)
        (proceeds am10 am11)
        (proceeds am11 pm12)
        (proceeds pm12 pm1)
        (proceeds pm1 pm2)
        (proceeds pm2 pm3)
        (proceeds pm3 pm4)
        (proceeds pm4 pm5)
        (proceeds pm5 pm6)
        (proceeds pm6 pm7)
        (proceeds pm7 pm8)
        (proceeds pm8 pm9)
        (proceeds pm9 pm10)
        (proceeds pm10 pm11)
        (proceeds pm11 am6)
        (time_of_day am6)


        (network_hardwear n1 switch)
        (not_connected_to_network d1 n1)
        (not_connected_to_network d2 n1)
        (not_connected_to_network d3 n1)
        (not_connected_to_network d4 n1)
        (not_connected_to_network d5 n1)

         ; d1 def
        (is_compromised d1)
        (trigger_at_time d1 am7)
        (trigger_at_time d1 am8)
        (trigger_at_time d1 pm4)
        (trigger_at_time d1 pm5)

        ; d2 def
        (has_pass d2 weak_password)
        (has_pass d3 weak_password)
        (trigger_at_time d1 pm6)


        ; d3 def
        (has_pass d3 strong_password)

        ; d4 def
        (does_encrypt d4)
        (open_TCP_23_port d4)

        ; d5 def
        (no_auth_firmwear d5)

        (=(trigger_count d1) 0)
        (=(trigger_count d2) 0)
        (=(trigger_count d3) 0)
        (=(trigger_count d4) 0)
        (=(trigger_count d5) 0)

        (=(max_trigger_count d1) 5)
        (=(max_trigger_count d2) 5)
        (=(max_trigger_count d3) 5)
        (=(max_trigger_count d4) 5)
        (=(max_trigger_count d5) 5)

        (=(trigger_length d1) 5)
        (=(trigger_length d2) 1)
        (=(trigger_length d3) 5)
        (=(trigger_length d4) 5)
        (=(trigger_length d5) 5)
    )

    (:goal (and
    ;todo: put the goal condition here
        (is_compromised d2)
        (is_compromised d3)
        (is_compromised d4)
        (is_compromised d5)
        (time_of_day pm11)
    ))

    ;un-comment the following line if metric is needed
    ;(:metric minimize (???))
)
