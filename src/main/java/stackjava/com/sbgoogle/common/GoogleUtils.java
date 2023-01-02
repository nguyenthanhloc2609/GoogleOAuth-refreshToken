package stackjava.com.sbgoogle.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class GoogleUtils {

	@Autowired
	private Environment env;

	public String getToken(final String code) throws ClientProtocolException, IOException {
		String link = env.getProperty("google.link.get.token");

		String response = Request.Post(link)
				.bodyForm(Form.form().add("client_id", env.getProperty("google.app.id"))
						.add("client_secret", env.getProperty("google.app.secret"))
						.add("redirect_uri", env.getProperty("google.redirect.uri")).add("code", code)
						.add("grant_type", "authorization_code").build())
				.execute().returnContent().asString();

		ObjectMapper mapper = new ObjectMapper();
		JsonNode node1 = mapper.readTree(response).get("access_token");
		JsonNode node2 = mapper.readTree(response).get("refresh_token");
		String refresh_token = node2.textValue();
		String newAcc = refreshToken(refresh_token);
		System.out.println("newAcc"+newAcc);
		return node1.textValue();
	}

	public GooglePojo getUserInfo(final String accessToken) throws ClientProtocolException, IOException {
		String link = env.getProperty("google.link.get.user_info") + accessToken;
		String response = Request.Get(link).execute().returnContent().asString();
		ObjectMapper mapper = new ObjectMapper();
		GooglePojo googlePojo = mapper.readValue(response, GooglePojo.class);
		System.out.println(googlePojo);
		return googlePojo;

	}

	public UserDetails buildUser(GooglePojo googlePojo) {
		boolean enabled = true;
		boolean accountNonExpired = true;
		boolean credentialsNonExpired = true;
		boolean accountNonLocked = true;
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		UserDetails userDetail = new User(googlePojo.getEmail(),
				"", enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		return userDetail;
	}

	public String refreshToken(final String refresh_token) throws ClientProtocolException, IOException {
		// "client_secret="+env.getProperty("google.app.secret")+"&grant_type=refresh_token&refresh_token="+refresh_token+"&client_id="+env.getProperty("google.app.id");
		System.out.println(refresh_token);
		String link = env.getProperty("google.link.get.token");

		String response = Request.Post(link)
				.bodyForm(Form.form().add("client_id", env.getProperty("google.app.id"))
						.add("client_secret", env.getProperty("google.app.secret"))
						.add("redirect_uri", env.getProperty("google.redirect.uri"))
						.add("refresh_token", refresh_token)
						.add("grant_type", "refresh_token").build())
				.execute().returnContent().asString();

		ObjectMapper mapper = new ObjectMapper();
		JsonNode node = mapper.readTree(response).get("access_token");
		return node.textValue();
	}

}
