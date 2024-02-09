###### Having a permissive Cross-Origin Resource Sharing policy is security-sensitive

Security Hotspot
Minor

    Available SinceDec 19, 2023
    SonarQube (Java)

Having a permissive Cross-Origin Resource Sharing policy is security-sensitive. It has led in the past to the following vulnerabilities:

    CVE-2018-0269
    CVE-2017-14460

Same origin policy in browsers prevents, by default and for security-reasons, a javascript frontend to perform a cross-origin HTTP request to a resource that has a different origin (domain, protocol, or port) from its own. The requested target can append additional HTTP headers in response, called CORS, that act like directives for the browser and change the access control policy / relax the same origin policy.


###### Ask Yourself Whether

    You don’t trust the origin specified, example: Access-Control-Allow-Origin: untrustedwebsite.com.
    Access control policy is entirely disabled: Access-Control-Allow-Origin: *
    Your access control policy is dynamically defined by a user-controlled input like origin header.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

Java servlet framework:

@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    resp.setHeader("Content-Type", "text/plain; charset=utf-8");
    resp.setHeader("Access-Control-Allow-Origin", "*"); // Sensitive
    resp.setHeader("Access-Control-Allow-Credentials", "true");
    resp.setHeader("Access-Control-Allow-Methods", "GET");
    resp.getWriter().write("response");
}

Spring MVC framework:

    CrossOrigin

@CrossOrigin // Sensitive
@RequestMapping("")
public class TestController {
    public String home(ModelMap model) {
        model.addAttribute("message", "ok ");
        return "view";
    }
}

    cors.CorsConfiguration

CorsConfiguration config = new CorsConfiguration();
config.addAllowedOrigin("*"); // Sensitive
config.applyPermitDefaultValues(); // Sensitive

    servlet.config.annotation.CorsConfiguration

class Insecure implements WebMvcConfigurer {
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/**")
      .allowedOrigins("*"); // Sensitive
  }
}

User-controlled origin:

public ResponseEntity<String> userControlledOrigin(@RequestHeader("Origin") String origin) {
  HttpHeaders responseHeaders = new HttpHeaders();
  responseHeaders.add("Access-Control-Allow-Origin", origin); // Sensitive

  return new ResponseEntity<>("content", responseHeaders, HttpStatus.CREATED);
}



######## Recommended Secure Coding Practices

    The Access-Control-Allow-Origin header should be set only for a trusted origin and for specific resources.
    Allow only selected, trusted domains in the Access-Control-Allow-Origin header. Prefer whitelisting domains over blacklisting or allowing any domain (do not use * wildcard nor blindly return the Origin header content without any checks).

Compliant Solution

Java Servlet framework:

@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    resp.setHeader("Content-Type", "text/plain; charset=utf-8");
    resp.setHeader("Access-Control-Allow-Origin", "trustedwebsite.com"); // Compliant
    resp.setHeader("Access-Control-Allow-Credentials", "true");
    resp.setHeader("Access-Control-Allow-Methods", "GET");
    resp.getWriter().write("response");
}

Spring MVC framework:

    CrossOrigin

@CrossOrigin("trustedwebsite.com") // Compliant
@RequestMapping("")
public class TestController {
    public String home(ModelMap model) {
        model.addAttribute("message", "ok ");
        return "view";
    }
}

    cors.CorsConfiguration

CorsConfiguration config = new CorsConfiguration();
config.addAllowedOrigin("http://domain2.com"); // Compliant

    servlet.config.annotation.CorsConfiguration

class Safe implements WebMvcConfigurer {
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/**")
      .allowedOrigins("safe.com"); // Compliant
  }
}

User-controlled origin validated with an allow-list:

public ResponseEntity<String> userControlledOrigin(@RequestHeader("Origin") String origin) {
  HttpHeaders responseHeaders = new HttpHeaders();
  if (trustedOrigins.contains(origin)) {
    responseHeaders.add("Access-Control-Allow-Origin", origin);
  }

  return new ResponseEntity<>("content", responseHeaders, HttpStatus.CREATED);
}

See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    developer.mozilla.org - CORS
    developer.mozilla.org - Same origin policy
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP HTML5 Security Cheat Sheet - Cross Origin Resource Sharing
    MITRE, CWE-346 - Origin Validation Error
    MITRE, CWE-942 - Overly Permissive Cross-domain Whitelist
    SANS Top 25 - Porous Defenses

