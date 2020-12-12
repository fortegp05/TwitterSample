package com.example.TwitterSample

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.PropertySource
import org.springframework.core.env.Environment
import org.springframework.http.HttpStatus
import org.springframework.http.RequestEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import java.lang.StringBuilder
import java.net.URI
import java.net.URLEncoder
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.servlet.http.HttpSession

@SpringBootApplication
@Controller
@PropertySource("classpath:application.properties")
class TwitterSampleApplication{

	@Autowired
	var session: HttpSession? = null

	@Autowired
	var env: Environment? = null

	@GetMapping("request_token")
	fun request_token(): String {
		val consumerKey = env?.getProperty("oauth.consumerKey") ?: ""
		val consumerSecret = env?.getProperty("oauth.consumerSecret") ?: ""

		val requestTokenUrl = "https://api.twitter.com/oauth/request_token"
		val algorithm = "HMAC-SHA1"
		val nonce = UUID.randomUUID().toString()
		val oauthVersion = "1.0"
		val timestamp = (System.currentTimeMillis() / 1000).toString()

		val encodeStr = "UTF-8"

		val authorization: SortedMap<String, String> = sortedMapOf(
				Pair("oauth_consumer_key", consumerKey),
				Pair("oauth_signature_method", algorithm),
				Pair("oauth_timestamp", timestamp.toString()),
				Pair("oauth_nonce", nonce),
				Pair("oauth_version", oauthVersion)
		)

		// signatureBaseの取得
		val authorizationBuilder = StringBuilder()
		authorization.map {authorizationBuilder.append("&${it.key}=${it.value}") }
		val signatureBaseStrParamsStr = URLEncoder.encode(authorizationBuilder.substring(1), encodeStr)
		val signatureBaseStr =
				"POST&${URLEncoder.encode(requestTokenUrl, encodeStr)}&" +
						"${signatureBaseStrParamsStr}"

		// HMAC-SHA1する
		val encodeConsumerSecretStr = "${URLEncoder.encode(consumerSecret, encodeStr)}&"
		val signingKey = SecretKeySpec(encodeConsumerSecretStr.toByteArray(), "HmacSHA1")
		val mac = Mac.getInstance(signingKey.algorithm)
		mac.init(signingKey)
		val macBytes = mac.doFinal(signatureBaseStr.toByteArray())

		// 結果をBase64してsignature取得
		val signature: String = Base64.getEncoder().encodeToString(macBytes)

		// authorizationParams作成
		authorization["oauth_signature"] = signature
		val authorizationHeaderBuilder = StringBuilder()
		authorization.map {
			authorizationHeaderBuilder.append(", ${it.key}" +
					"=\"${URLEncoder.encode(it.value, encodeStr)}\"")
		}
		val authorizationHeader = "OAuth ${authorizationHeaderBuilder.substring(2)}"

		// リクエスト送信
		val restTemplate: RestTemplate = RestTemplate()
		val requestTokenEntity: RequestEntity<String> =
				RequestEntity
						.post(URI(requestTokenUrl))
						.header("Authorization", authorizationHeader)
						.body("")
		val responseStr =  restTemplate.exchange(requestTokenEntity, String::class.java)
		System.out.println(responseStr.statusCode)
		System.out.println(responseStr.statusCodeValue)
		System.out.println(responseStr.body)

		if (responseStr.statusCodeValue != HttpStatus.OK.value()) return ""

		val responseArray = responseStr.body?.split("&")
		val oauth_token = responseArray?.get(0)?.split("=")?.get(1)
		val oauth_token_secret = responseArray?.get(1)?.split("=")?.get(1)

		session?.setAttribute("oauthTokenSecret", oauth_token_secret)

		return "redirect:http://twitter.com/oauth/authorize?oauth_token=${oauth_token}"
	}

	@GetMapping("callback")
	fun callback(
			@RequestParam(value = "oauth_token") oauthToken: String,
			@RequestParam(value = "oauth_verifier") oauthVerifier: String
	): String {
		val consumerKey = env?.getProperty("oauth.consumerKey") ?: ""
		val consumerSecret = env?.getProperty("oauth.consumerSecret") ?: ""

		val oauthTokenUrl = "https://api.twitter.com/oauth/access_token"
		val algorithm = "HMAC-SHA1"
		val nonce = UUID.randomUUID().toString()
		val oauthVersion = "1.0"
		val timestamp = (System.currentTimeMillis() / 1000).toString()

		val encodeStr = "UTF-8"

		val authorization: SortedMap<String, String> = sortedMapOf(
				Pair("oauth_consumer_key", consumerKey),
				Pair("oauth_signature_method", algorithm),
				Pair("oauth_timestamp", timestamp.toString()),
				Pair("oauth_nonce", nonce),
				Pair("oauth_version", oauthVersion),
				Pair("oauth_token", oauthToken),
				Pair("oauth_verifier", oauthVerifier)
		)

		val oauthTokenSecret = session?.getAttribute("oauthTokenSecret")

		// signatureBaseの取得
		val authorizationBuilder = StringBuilder()
		authorization.map {authorizationBuilder.append("&${it.key}=${it.value}") }
		val signatureBaseStrParamsStr =
				URLEncoder.encode(authorizationBuilder.substring(1), encodeStr)
		val signatureBaseStr =
				"POST&${URLEncoder.encode(oauthTokenUrl, encodeStr)}&${signatureBaseStrParamsStr}"

		// HMAC-SHA1する
		val encodeConsumerSecretStr =
				"${URLEncoder.encode(consumerSecret, encodeStr)}&" +
						URLEncoder.encode(oauthTokenSecret.toString(), encodeStr)
		val signingKey = SecretKeySpec(encodeConsumerSecretStr.toByteArray(), "HmacSHA1")
		val mac = Mac.getInstance(signingKey.algorithm)
		mac.init(signingKey)
		val macBytes = mac.doFinal(signatureBaseStr.toByteArray())

		// 結果をBase64してsignature取得
		val signature: String = Base64.getEncoder().encodeToString(macBytes)

		// authorizationParams作成
		authorization["oauth_signature"] = signature
		val authorizationHeaderBuilder = StringBuilder()
		authorization.map {
			authorizationHeaderBuilder.append(", ${it.key}=" +
					"\"${URLEncoder.encode(it.value, encodeStr)}\"")
		}
		val authorizationHeader = "OAuth ${authorizationHeaderBuilder.substring(2)}"

		// リクエスト送信
		val restTemplate: RestTemplate = RestTemplate()
		val requestTokenEntity: RequestEntity<String> =
				RequestEntity
						.post(URI(oauthTokenUrl))
						.header("Authorization", authorizationHeader)
						.body("")
		val responseStr =  restTemplate.exchange(requestTokenEntity, String::class.java)
		System.out.println(responseStr.statusCode)
		System.out.println(responseStr.statusCodeValue)
		System.out.println(responseStr.body)

		return ""
	}
}

fun main(args: Array<String>) {
	runApplication<TwitterSampleApplication>(*args)
}
