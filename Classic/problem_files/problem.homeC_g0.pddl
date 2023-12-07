(define (problem pentesting)
	(:domain home_network)
	(:objects 
		 doorbell0 security_cam0 security_cam1 printer0 google_home0 google_home1 speaker0 light_sw0 light_sw1 light_sw2 - device
		 n1 - network
	)
	(:init
		(network_hardwear n1 switch)

		(is_connected_to_network doorbell0 n1)
		(is_connected_to_network security_cam0 n1)
		(is_connected_to_network security_cam1 n1)
		(is_connected_to_network printer0 n1)
		(is_connected_to_network google_home0 n1)
		(is_connected_to_network google_home1 n1)
		(is_connected_to_network speaker0 n1)
		(is_connected_to_network light_sw0 n1)
		(is_connected_to_network light_sw1 n1)
		(is_connected_to_network light_sw2 n1)
		;Vulnerability Initializaton
		(no_auth_firmwear printer0)
		(is_compromised security_cam0)
		(does_encrypt light_sw1)
		(open_TCP_23_port light_sw1)
		(is_compromised security_cam0)
	)

	(:goal (and
		(is_compromised printer0)
	))
)