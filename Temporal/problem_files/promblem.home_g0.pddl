(define (problem pentesting)
	(:domain home_network_T)
	(:objects
		 doorbell0 security_cam0 security_cam1 printer0 google_home0 google_home1 speaker0 light_sw0 light_sw1 light_sw2 - device
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

		; Define Network Connections
		(network_hardwear n1 switch)

		; assume all devices are disconnected

		; doorbell initialization
		; doorbell 0
		(trigger_at_time doorbell0 am7)
		(trigger_at_time doorbell0 am8)
		(trigger_at_time doorbell0 pm5)
		(trigger_at_time doorbell0 pm6)
		(not_connected_to_network doorbell0 n1)
		(=(max_trigger_count doorbell0) 1)
		(=(trigger_length doorbell0) 1)
		(=(trigger_count doorbell0) 0)



		; security camera initialization
		; security_cam 0
		(trigger_at_time security_cam0 am7)
		(trigger_at_time security_cam0 am8)
		(trigger_at_time security_cam0 pm12)
		(trigger_at_time security_cam0 pm5)
		(trigger_at_time security_cam0 pm6)

		(not_connected_to_network security_cam0 n1)
		(=(max_trigger_count security_cam0) 5)
		(=(trigger_length security_cam0) 5)
		(=(trigger_count security_cam0) 0)

		; security_cam 1
		(trigger_at_time security_cam1 am7)
		(trigger_at_time security_cam1 am8)
		(trigger_at_time security_cam1 pm12)
		(trigger_at_time security_cam1 pm5)
		(trigger_at_time security_cam1 pm6)

		(not_connected_to_network security_cam1 n1)
		(=(max_trigger_count security_cam1) 5)
		(=(trigger_length security_cam1) 5)
		(=(trigger_count security_cam1) 0)


		; printer initialization
		; printer 0
		(trigger_at_time printer0 pm7)
		(trigger_at_time printer0 pm6)

		(not_connected_to_network printer0 n1)
		(=(max_trigger_count printer0) 2)
		(=(trigger_length printer0) 2)
		(=(trigger_count printer0) 0)


		; google home initialization
		; google_home 0
		(trigger_at_time google_home0 am7)
		(trigger_at_time google_home0 pm8)
		(trigger_at_time google_home0 pm10)

		(not_connected_to_network google_home0 n1)
		(=(max_trigger_count google_home0) 2)
		(=(trigger_length google_home0) 2)
		(=(trigger_count google_home0) 0)

		; google_home 1
		(trigger_at_time google_home1 am7)
		(trigger_at_time google_home1 pm8)
		(trigger_at_time google_home1 pm10)

		(not_connected_to_network google_home1 n1)
		(=(max_trigger_count google_home1) 2)
		(=(trigger_length google_home1) 2)
		(=(trigger_count google_home1) 0)


		; speaker initialization
		; speaker 0
		(trigger_at_time speaker0 pm8)

		(not_connected_to_network speaker0 n1)
		(=(max_trigger_count speaker0) 1)
		(=(trigger_length speaker0) 45)
		(=(trigger_count speaker0) 0)


		; light switch initialization
		; light switch 0
		(trigger_at_time light_sw0 am6)
		(trigger_at_time light_sw0 am7)
		(trigger_at_time light_sw0 am8)
		(trigger_at_time light_sw0 pm12)
		(trigger_at_time light_sw0 pm1)
		(trigger_at_time light_sw0 pm2)
		(trigger_at_time light_sw0 pm5)
		(trigger_at_time light_sw0 pm6)
		(trigger_at_time light_sw0 pm7)
		(trigger_at_time light_sw0 pm8)
		(trigger_at_time light_sw0 pm9)
		(trigger_at_time light_sw0 pm10)


		(not_connected_to_network light_sw0 n1)
		(=(max_trigger_count light_sw0) 15)
		(=(trigger_length light_sw0) 1)
		(=(trigger_count light_sw0) 0)

		; light switch 1
		(trigger_at_time light_sw1 am6)
		(trigger_at_time light_sw1 am7)
		(trigger_at_time light_sw1 am8)
		(trigger_at_time light_sw1 pm12)
		(trigger_at_time light_sw1 pm1)
		(trigger_at_time light_sw1 pm2)
		(trigger_at_time light_sw1 pm5)
		(trigger_at_time light_sw1 pm6)
		(trigger_at_time light_sw1 pm7)
		(trigger_at_time light_sw1 pm8)
		(trigger_at_time light_sw1 pm9)
		(trigger_at_time light_sw1 pm10)


		(not_connected_to_network light_sw1 n1)
		(=(max_trigger_count light_sw1) 10)
		(=(trigger_length light_sw1) 1)
		(=(trigger_count light_sw1) 0)

		; light switch 2
		(trigger_at_time light_sw2 am6)
		(trigger_at_time light_sw2 am7)
		(trigger_at_time light_sw2 am8)
		(trigger_at_time light_sw2 pm12)
		(trigger_at_time light_sw2 pm1)
		(trigger_at_time light_sw2 pm2)
		(trigger_at_time light_sw2 pm5)
		(trigger_at_time light_sw2 pm6)
		(trigger_at_time light_sw2 pm7)
		(trigger_at_time light_sw2 pm8)
		(trigger_at_time light_sw2 pm9)
		(trigger_at_time light_sw2 pm10)


		(not_connected_to_network light_sw2 n1)
		(=(max_trigger_count light_sw2) 5)
		(=(trigger_length light_sw2) 1)
		(=(trigger_count light_sw2) 0)

		;Vulnerability Initializaton

		(no_auth_firmwear printer0)
		(does_encrypt light_sw1)
		(open_TCP_23_port light_sw1)

		;initial compromised device
		(is_compromised security_cam0)

	)

	(:goal (and

		(is_compromised printer0)
		(time_of_day pm11)
	))
)