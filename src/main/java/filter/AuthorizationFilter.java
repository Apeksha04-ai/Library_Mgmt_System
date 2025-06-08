package filter;

import java.io.IOException;

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
 * Filter to check user roles before accessing protected resources
 */
@WebFilter(urlPatterns = {"/views/admin/*"})
public class AuthorizationFilter implements Filter {
    
    // Role required to access protected resources
    private static final String LIBRARIAN_ROLE = "Librarian";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // Get the logged in user
        User user = SessionUtil.getLoggedInUser(httpRequest);
        
        // Check if user has the required role
        if (user != null && LIBRARIAN_ROLE.equals(user.getRole())) {
            // User has the required role, continue with the request
            chain.doFilter(request, response);
        } else {
            // User does not have the required role, redirect to access denied page
            String accessDeniedPage = httpRequest.getContextPath() + "/views/accessDenied.jsp";
            httpResponse.sendRedirect(accessDeniedPage);
        }
    }

    @Override
    public void destroy() {
        // Cleanup code if needed
    }
} 