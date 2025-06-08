package filter;

import java.io.IOException;

import dao.UserDAO;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import model.User;
import util.SessionUtil;

/**
 * Filter to check if user is authenticated before accessing secured resources
 */
@WebFilter(urlPatterns = {"/views/secured/*", "/views/dashboard/*", "/views/admin/*"})
public class AuthenticationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Check if user is logged in
        if (SessionUtil.isLoggedIn(httpRequest)) {
            // User is logged in, continue with the request
            chain.doFilter(request, response);
        } else {
            // Check for remember me cookie
            String rememberMe = SessionUtil.getCookieValue(httpRequest, SessionUtil.REMEMBER_ME_COOKIE);
            String email = SessionUtil.getCookieValue(httpRequest, SessionUtil.USER_EMAIL_COOKIE);
            
            if (rememberMe != null && email != null) {
                // Try to auto-login
                UserDAO userDAO = new UserDAO();
                User user = userDAO.getUserByEmail(email);
                
                if (user != null) {
                    // Auto-login successful, create session
                    SessionUtil.createUserSession(httpRequest, user);
                    chain.doFilter(request, response);
                    return;
                }
            }
            
            // Not logged in and auto-login failed, redirect to login page
            String loginPage = httpRequest.getContextPath() + "/views/login.jsp";
            httpResponse.sendRedirect(loginPage);
        }
    }

    @Override
    public void destroy() {
        // Cleanup code if needed
    }
} 