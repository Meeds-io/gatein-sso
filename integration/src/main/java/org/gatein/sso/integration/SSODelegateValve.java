/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.gatein.sso.integration;

import java.io.IOException;
import java.lang.reflect.Method;

import javax.management.MBeanRegistration;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.servlet.ServletException;

import org.apache.catalina.Contained;
import org.apache.catalina.Container;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * Delegates work to another valve configured through option 'delegateValveClassName'. It's possible to disable
 * delegation by boolean parameter 'ssoDelegationEnabled'.
 *
 * Actually delegation will be enabled only for SSO scenario, which require integration with Tomcat valves (SAML, SPNEGO)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSODelegateValve implements Valve, Contained, MBeanRegistration, Lifecycle
{
  private static final Log log = ExoLogger.getLogger(SSODelegateValve.class);

   // Injected by container
   // If true, then we are in SSO and we have delegate valve where we should resend all method calls
   // If false, we are not in SSO and we don't have delegate
   private boolean delegationEnabled;

   // Injected by container
   private String delegateValveClassName;

   // Delegate valve is not null only if we are in SSO mode and delegation is enabled
   // Delegate will be either SAML or SPNEGO valve
   private Valve delegate;

   // This is not null only if delegation is disabled
   private Valve next;

   // Catalina context
   private Container context;

   // Used only for SAML2 when acting as SP
   private String samlSPConfigFile;

   public void setDelegateValveClassName(String delegateValve)
   {
      this.delegateValveClassName = substituteSystemProperty(delegateValve);
      log.debug("delegateValveClassName: " + delegateValveClassName);
   }

   public void setSsoDelegationEnabled(String enabled)
   {
      enabled = substituteSystemProperty(enabled);
      this.delegationEnabled = Boolean.parseBoolean(enabled);
      log.debug("ssoDelegationEnabled: " + delegationEnabled);
   }

   public void setSamlSPConfigFile(String configFile)
   {
      this.samlSPConfigFile = substituteSystemProperty(configFile);
   }

   public Valve getNext()
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         return delegate.getNext();
      }
      else
      {
         return next;
      }
   }

   public void setNext(Valve valve)
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         delegate.setNext(valve);
      }
      else
      {
         this.next = valve;
      }

   }

   public void backgroundProcess()
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         delegate.backgroundProcess();
      }
   }

   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         delegate.invoke(request, response);
      }
      else
      {
         next.invoke(request, response);
      }
   }

   // CONTAINED methods

   public Container getContainer()
   {
      return context;
   }

   public void setContainer(Container container)
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Contained)
         {
            ((Contained) delegate).setContainer(container);
         }
      }
      this.context = container;

   }

   // MBeanRegistration methods

   public ObjectName preRegister(MBeanServer server, ObjectName name) throws Exception
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof MBeanRegistration)
         {
            return ((MBeanRegistration) delegate).preRegister(server,name);
         }
      }
      return name;
   }

   public void postRegister(Boolean registrationDone)
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof MBeanRegistration)
         {
            ((MBeanRegistration) delegate).postRegister(registrationDone);
         }
      }
   }

   public void preDeregister() throws Exception
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof MBeanRegistration)
         {
            ((MBeanRegistration) delegate).preDeregister();
         }
      }
   }

   public void postDeregister()
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof MBeanRegistration)
         {
            ((MBeanRegistration) delegate).postDeregister();
         }
      }
   }

   public void addLifecycleListener(LifecycleListener listener)
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Lifecycle)
         {
            ((Lifecycle) delegate).addLifecycleListener(listener);
            return;
         }
      }
   }

   public LifecycleListener[] findLifecycleListeners()
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Lifecycle)
         {
            return ((Lifecycle) delegate).findLifecycleListeners();
         }
      }
      return new LifecycleListener[0];
   }

   public void removeLifecycleListener(LifecycleListener listener)
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Lifecycle)
         {
            ((Lifecycle) delegate).removeLifecycleListener(listener);
            return;
         }
      }
   }

   public void start() throws LifecycleException
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Lifecycle)
         {
            ((Lifecycle) delegate).start();
         }
      }
   }

   public void stop() throws LifecycleException
   {
      if (delegationEnabled)
      {
         Valve delegate = getOrLoadDelegate(delegateValveClassName);
         if (delegate instanceof Lifecycle)
         {
            ((Lifecycle) delegate).stop();
         }
      }
   }

   private Valve getOrLoadDelegate(String className)
   {
      if (delegate == null)
      {
         if (className == null)
         {
            throw new IllegalStateException("Delegate className is null in SSODelegateValve");
         }

         Class<Valve> delegateClass = (Class<Valve>)SSOUtils.loadClass(className);
         try
         {
            this.delegate = delegateClass.newInstance();
            log.info("Delegating valve created successfully: " + delegate);
         }
         catch (Exception e)
         {
            throw new RuntimeException("Can't instantiate " + delegateClass, e);
         }

         // Update location of configFile for SAML2 SP. Little hack but sufficient for our purpose
         if (this.samlSPConfigFile != null)
         {
            try
            {
               Method m = delegateClass.getMethod("setConfigFile", String.class);
               m.invoke(delegate, samlSPConfigFile);
               log.info("Picketlink configuration file successfully set to location: " + samlSPConfigFile);
            }
            catch (Exception e)
            {
               log.trace("Can't set SAML config file. Method 'setConfigFile' not supported on class " + delegateClass, e);
            }
         }
      }

      return delegate;
   }

   private String substituteSystemProperty(String input)
   {
      // We need to replace system properties by ourselves, so we need to define in configuration like #{prop} instead of ${prop}
      input = input.replace("#", "$");
      return SSOUtils.substituteSystemProperty(input);
   }

  @Override
  public void init() throws LifecycleException {
    if (delegationEnabled)
    {
       Valve delegate = getOrLoadDelegate(delegateValveClassName);
       if (delegate instanceof Lifecycle)
       {
          ((Lifecycle) delegate).init();
       }
    }
  }

  @Override
  public void destroy() throws LifecycleException {
    if (delegationEnabled)
    {
       Valve delegate = getOrLoadDelegate(delegateValveClassName);
       if (delegate instanceof Lifecycle)
       {
          ((Lifecycle) delegate).destroy();
       }
    }
  }

  @Override
  public LifecycleState getState() {
    if (delegationEnabled)
    {
       Valve delegate = getOrLoadDelegate(delegateValveClassName);
       if (delegate instanceof Lifecycle)
       {
          return ((Lifecycle) delegate).getState();
       }
    }
    return null;
  }

  @Override
  public String getStateName() {
    if (delegationEnabled)
    {
       Valve delegate = getOrLoadDelegate(delegateValveClassName);
       if (delegate instanceof Lifecycle)
       {
          return ((Lifecycle) delegate).getStateName();
       }
    }
    return null;
  }

  @Override
  public boolean isAsyncSupported() {
    if (delegationEnabled)
    {
       Valve delegate = getOrLoadDelegate(delegateValveClassName);
       if (delegate instanceof Valve)
       {
          return ((Valve) delegate).isAsyncSupported();
       }
    }
    return false;
  }
}
