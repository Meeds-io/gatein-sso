package org.jboss.security;

import java.security.Principal;
import java.util.Enumeration;

public interface Group extends Principal {

  public boolean addMember(Principal user);

  public boolean removeMember(Principal user);

  public boolean isMember(Principal member);

  public Enumeration<? extends Principal> members();

}
