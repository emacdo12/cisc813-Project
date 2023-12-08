(define (problem pentesting)
	(:domain home_network_T)
	(:objects
		 doorbell0 security_cam0 security_cam1 security_cam2 security_cam3 security_cam4 printer0 speaker0 light_sw0 light_sw1 - device
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
		(=(max_trigger_count doorbell0) 2)
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

		; security_cam 2
		(trigger_at_time security_cam2 am7)
		(trigger_at_time security_cam2 am8)
		(trigger_at_time security_cam2 pm12)
		(trigger_at_time security_cam2 pm5)
		(trigger_at_time security_cam2 pm6)

		(not_connected_to_network security_cam2 n1)
		(=(max_trigger_count security_cam2) 5)
		(=(trigger_length security_cam2) 5)
		(=(trigger_count security_cam2) 0)

		; security_cam 3
		(trigger_at_time security_cam3 am7)
		(trigger_at_time security_cam3 am8)
		(trigger_at_time security_cam3 pm12)
		(trigger_at_time security_cam3 pm5)
		(trigger_at_time security_cam3 pm6)

		(not_connected_to_network security_cam3 n1)
		(=(max_trigger_count security_cam3) 5)
		(=(trigger_length security_cam3) 5)
		(=(trigger_count security_cam3) 0)

		; security_cam 4
		(trigger_at_time security_cam4 am7)
		(trigger_at_time security_cam4 am8)
		(trigger_at_time security_cam4 pm12)
		(trigger_at_time security_cam4 pm5)
		(trigger_at_time security_cam4 pm6)

		(not_connected_to_network security_cam4 n1)
		(=(max_trigger_count security_cam4) 5)
		(=(trigger_length security_cam4) 5)
		(=(trigger_count security_cam4) 0)


		; printer initialization
		; printer 0
		(trigger_at_time printer0 pm7)
		(trigger_at_time printer0 pm6)

		(not_connected_to_network printer0 n1)
		(=(max_trigger_count printer0) 2)
		(=(trigger_length printer0) 2)
		(=(trigger_count printer0) 0)


		; speaker initialization
		; speaker 0
		(trigger_at_time speaker0 am8)
		(trigger_at_time speaker0 am7)
		(trigger_at_time speaker0 pm8)

		(not_connected_to_network speaker0 n1)
		(=(max_trigger_count speaker0) 2)
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
		(=(max_trigger_count light_sw0) 12)
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
		(=(max_trigger_count light_sw1) 12)
		(=(trigger_length light_sw1) 1)
		(=(trigger_count light_sw1) 0)

		;Vulnerability Initializaton

		(has_pass security_cam0 weak_password)
		(has_pass security_cam1 weak_password)
		(has_pass security_cam2 weak_password)
		(has_pass security_cam3 weak_password)
		(has_pass security_cam4 weak_password)

		;initial compromised device
		(is_compromised speaker0)

	)

	(:goal (and

		(is_compromised security_cam0)
		(is_compromised security_cam1)
		(is_compromised security_cam2)
		(is_compromised security_cam3)
		(is_compromised security_cam4)
		(time_of_day pm11)
	))
)