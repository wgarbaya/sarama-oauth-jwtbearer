# JWT Token provider for IBM/sarama

Minimal code to configure "github.com/IBM/sarama" token provider when used with Kafka enable Oauth
Tested only with Keycloak

	var config = btKafka.Confg{
		ClientID: "kafka3",
		Audience: "http://172.17.0.1:8585/realms/kafka",
		TokenURL: "http://172.17.0.1:8585/realms/kafka/protocol/openid-connect/token",
		PkPath:   "sample_key",
		Scope:    "kafka-client",
	}

 	config := sarama.NewConfig()
	config.Version = sarama.V2_7_0_0
	config.Net.SASL.Enable = true
	config.Net.SASL.Mechanism = sarama.SASLTypeOAuth
	config.Net.SASL.TokenProvider = &btKafka.JWTBTokenProvider{Cfg: config}


## References

- damiannolan/sasl: Similar (this work is based on this source) but for client/secret based Oauth https://github.com/damiannolan/sasl
