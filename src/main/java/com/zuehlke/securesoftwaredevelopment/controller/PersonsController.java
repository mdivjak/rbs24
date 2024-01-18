package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.Role;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RoleRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository, RoleRepository roleRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/persons/{id}")
    public String person(@PathVariable int id, Model model, HttpSession session)
            throws AccessDeniedException {
        LOG.info("Viewing person " + id);
        User user = SecurityUtil.getCurrentUser();
        boolean isCurrentUser = user.getId() == id;

        List<Role> roles = roleRepository.findByUserId(SecurityUtil.getCurrentUser().getId());
        boolean isAdmin = false;

        for(Role role : roles)
        {
            if(role.getName().equals("ADMIN"))
            {
                isAdmin = true;
            }
        }

        if(!isAdmin && !isCurrentUser)
        {
            throw new AccessDeniedException("Forbidden");
        }

        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        LOG.info("Viewing my profile");
        User user = (User) authentication.getPrincipal();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id, HttpSession session, @RequestParam("csrfToken")String csrfToken)
            throws AccessDeniedException {
        LOG.info("Deleting person " + id);
        User user = SecurityUtil.getCurrentUser();
        boolean isCurrentUser = user.getId() == id;

        List<Role> roles = roleRepository.findByUserId(SecurityUtil.getCurrentUser().getId());
        boolean isAdmin = false;

        for(Role role : roles)
        {
            if(role.getName().equals("ADMIN"))
            {
                isAdmin = true;
            }
        }

        if(!isAdmin && !isCurrentUser)
        {
            LOG.warn("Not an admin and not current user");
            throw new AccessDeniedException("Forbidden");
        }

        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if(!csrf.equals(csrfToken))
        {
            LOG.warn("Invalid CSRF token");
            throw new AccessDeniedException("Forbidden");
        }
        personRepository.delete(id);
        userRepository.delete(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, Authentication authentication, HttpSession session, @RequestParam("csrfToken") String csrfToken)
            throws AccessDeniedException {
        LOG.info("Updating person " + person.getId());
        User user = SecurityUtil.getCurrentUser();
        boolean isCurrentUser = user.getId() == Integer.parseInt(person.getId());

        List<Role> roles = roleRepository.findByUserId(SecurityUtil.getCurrentUser().getId());
        boolean isAdmin = false;

        for(Role role : roles)
        {
            if(role.getName().equals("ADMIN"))
            {
                isAdmin = true;
            }
        }

        if(!isAdmin && !isCurrentUser)
        {
            LOG.warn("Not an admin and not a current user");
            throw new AccessDeniedException("Forbidden");
        }

        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if(!csrf.equals(csrfToken))
        {
            LOG.warn("Invalid CSRF token");
            throw new AccessDeniedException("Forbidden");
        }
        personRepository.update(person);
        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        LOG.info("Viewing persons");
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        LOG.info("Searching persons");
        return personRepository.search(searchTerm);
    }
}
