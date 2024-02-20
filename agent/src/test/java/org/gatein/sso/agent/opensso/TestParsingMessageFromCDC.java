/*
 *  JBoss, a division of Red Hat
 *  Copyright 2012, Red Hat Middleware, LLC, and individual contributors as indicated
 *  by the @authors tag. See the copyright.txt in the distribution for a
 *  full listing of individual contributors.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this software; if not, write to the Free
 *  Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301 USA, or see the FSF site: http://www.fsf.org.
 *
 */

package org.gatein.sso.agent.opensso;

import junit.framework.TestCase;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestParsingMessageFromCDC extends TestCase
{
  private static Log          log                  = ExoLogger.getLogger(TestParsingMessageFromCDC.class);

   // SSO token is not URL encoded in OpenAM
   private static final String TEST_MESSAGE_OPENAM = "PGxpYjpBdXRoblJlc3BvbnNlIHhtbG5zOmxpYj0iaHR0cDovL3Byb2plY3RsaWJlcnR5Lm9yZy9zY2hlbWFzL2NvcmUvMjAwMi8xMiIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMDpwcm90b2NvbCIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIFJlc3BvbnNlSUQ9InNmYWMwNTU4MmJkMmMwNzgwZTg3Yjc3YTUzOTkxNjYxOTA3ZTk1ZDdhIiAgSW5SZXNwb25zZVRvPSIxMjQiIE1ham9yVmVyc2lvbj0iMSIgTWlub3JWZXJzaW9uPSIwIiBJc3N1ZUluc3RhbnQ9IjIwMTItMDQtMTJUMDc6NDY6MTVaIj48c2FtbHA6U3RhdHVzPgo8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0ic2FtbHA6U3VjY2VzcyI+Cjwvc2FtbHA6U3RhdHVzQ29kZT4KPC9zYW1scDpTdGF0dXM+CjxzYW1sOkFzc2VydGlvbiAgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmFzc2VydGlvbiIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgIHhtbG5zOmxpYj0iaHR0cDovL3Byb2plY3RsaWJlcnR5Lm9yZy9zY2hlbWFzL2NvcmUvMjAwMi8xMiIgIGlkPSJzYTMxOWVmZTljNGQzYzUyNDQwNzRhMmFjMTg1MmY4MWJhYWNjYjE0NzAxIiBNYWpvclZlcnNpb249IjEiIE1pbm9yVmVyc2lvbj0iMCIgQXNzZXJ0aW9uSUQ9InNhMzE5ZWZlOWM0ZDNjNTI0NDA3NGEyYWMxODUyZjgxYmFhY2NiMTQ3MDEiIElzc3Vlcj0iaHR0cDovL2xvY2FsaG9zdDo4ODg4L29wZW5zc28vY2Rjc2VydmxldCIgSXNzdWVJbnN0YW50PSIyMDEyLTA0LTEyVDA3OjQ2OjE1WiIgSW5SZXNwb25zZVRvPSIxMjQiIHhzaTp0eXBlPSJsaWI6QXNzZXJ0aW9uVHlwZSI+CjxzYW1sOkNvbmRpdGlvbnMgIE5vdEJlZm9yZT0iMjAxMi0wNC0xMlQwNzo0NjoxNVoiIE5vdE9uT3JBZnRlcj0iMjAxMi0wNC0xMlQwNzo0NzoxNVoiID4KPHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbkNvbmRpdGlvbj4KPHNhbWw6QXVkaWVuY2U+aHR0cDovL2pvc3NvLTAxLmxvY2FsLm5ldHdvcms6ODA4MC9wb3J0YWwvaW5pdGlhdGVzc29sb2dpbi8/UmVhbG09Z2dhdGVpbjwvc2FtbDpBdWRpZW5jZT4KPC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb25Db25kaXRpb24+Cjwvc2FtbDpDb25kaXRpb25zPgo8c2FtbDpBdXRoZW50aWNhdGlvblN0YXRlbWVudCAgQXV0aGVudGljYXRpb25NZXRob2Q9IkF1dGhlbnRpY2F0aW9uUGx1Z2luIiBBdXRoZW50aWNhdGlvbkluc3RhbnQ9IjIwMTItMDQtMTJUMDc6NDY6MTVaIiBSZWF1dGhlbnRpY2F0ZU9uT3JBZnRlcj0iMjAxMi0wNC0xMlQwNzo0NzoxNVoiIHhzaTp0eXBlPSJsaWI6QXV0aGVudGljYXRpb25TdGF0ZW1lbnRUeXBlIj48c2FtbDpTdWJqZWN0ICAgeHNpOnR5cGU9ImxpYjpTdWJqZWN0VHlwZSI+PHNhbWw6TmFtZUlkZW50aWZpZXIgTmFtZVF1YWxpZmllcj0iaHR0cDovL2xvY2FsaG9zdDo4ODg4L29wZW5zc28vY2Rjc2VydmxldCI+QVFJQzV3TTJMWTRTZmN3QU42aGppak9DUE8xdTdVdXJFbjlEdnFGWEt6d0ZzaTAuKkFBSlRTUUFDTURFLio8L3NhbWw6TmFtZUlkZW50aWZpZXI+CjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24+CjxzYW1sOkNvbmZpcm1hdGlvbk1ldGhvZD51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6Y206YmVhcmVyPC9zYW1sOkNvbmZpcm1hdGlvbk1ldGhvZD4KPC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+CjxsaWI6SURQUHJvdmlkZWROYW1lSWRlbnRpZmllciAgTmFtZVF1YWxpZmllcj0iaHR0cDovL2xvY2FsaG9zdDo4ODg4L29wZW5zc28vY2Rjc2VydmxldCIgPkFRSUM1d00yTFk0U2Zjd0FONmhqaWpPQ1BPMXU3VXVyRW45RHZxRlhLendGc2kwLipBQUpUU1FBQ01ERS4qPC9saWI6SURQUHJvdmlkZWROYW1lSWRlbnRpZmllcj4KPC9zYW1sOlN1YmplY3Q+PHNhbWw6U3ViamVjdExvY2FsaXR5ICBJUEFkZHJlc3M9IjEyNy4wLjAuMSIgRE5TQWRkcmVzcz0ibG9jYWxob3N0IiAvPjxsaWI6QXV0aG5Db250ZXh0PjxsaWI6QXV0aG5Db250ZXh0Q2xhc3NSZWY+aHR0cDovL3d3dy5wcm9qZWN0bGliZXJ0eS5vcmcvc2NoZW1hcy9hdXRoY3R4L2NsYXNzZXMvUGFzc3dvcmQ8L2xpYjpBdXRobkNvbnRleHRDbGFzc1JlZj48bGliOkF1dGhuQ29udGV4dFN0YXRlbWVudFJlZj5odHRwOi8vd3d3LnByb2plY3RsaWJlcnR5Lm9yZy9zY2hlbWFzL2F1dGhjdHgvY2xhc3Nlcy9QYXNzd29yZDwvbGliOkF1dGhuQ29udGV4dFN0YXRlbWVudFJlZj48L2xpYjpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhlbnRpY2F0aW9uU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+CjxsaWI6UHJvdmlkZXJJRD5odHRwOi8vbG9jYWxob3N0Ojg4ODgvb3BlbnNzby9jZGNzZXJ2bGV0PC9saWI6UHJvdmlkZXJJRD48L2xpYjpBdXRoblJlc3BvbnNlPgo=";

   // SSO token is URL encoded in OpenSSO
   private static final String TEST_MESSAGE_OPENSSO = "PGxpYjpBdXRoblJlc3BvbnNlIHhtbG5zOmxpYj0iaHR0cDovL3Byb2plY3RsaWJlcnR5Lm9yZy9zY2hlbWFzL2NvcmUvMjAwMi8xMiIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMDpwcm90b2NvbCIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIFJlc3BvbnNlSUQ9InNmZTNjNWI5MzIwZDA5MjM5MGUxYmJjMmE0MzE4NzcwM2NkOTM0NDY1IiAgSW5SZXNwb25zZVRvPSI0NzU3MyIgTWFqb3JWZXJzaW9uPSIxIiBNaW5vclZlcnNpb249IjAiIElzc3VlSW5zdGFudD0iMjAxMi0wNC0xMlQyMjoxMTo0MloiPjxzYW1scDpTdGF0dXM+CjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJzYW1scDpTdWNjZXNzIj4KPC9zYW1scDpTdGF0dXNDb2RlPgo8L3NhbWxwOlN0YXR1cz4KPHNhbWw6QXNzZXJ0aW9uICB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6YXNzZXJ0aW9uIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiAgeG1sbnM6bGliPSJodHRwOi8vcHJvamVjdGxpYmVydHkub3JnL3NjaGVtYXMvY29yZS8yMDAyLzEyIiAgaWQ9InNmMzQ3NTgzODZhMWNjYjI2YmVjMzc4ZjQxM2U1ZDE1MGU4MDMzYWQyMDEiIE1ham9yVmVyc2lvbj0iMSIgTWlub3JWZXJzaW9uPSIwIiBBc3NlcnRpb25JRD0ic2YzNDc1ODM4NmExY2NiMjZiZWMzNzhmNDEzZTVkMTUwZTgwMzNhZDIwMSIgSXNzdWVyPSJodHRwOi8vbG9jYWxob3N0Ojg4ODgvb3BlbnNzby9jZGNzZXJ2bGV0IiBJc3N1ZUluc3RhbnQ9IjIwMTItMDQtMTJUMjI6MTE6NDJaIiBJblJlc3BvbnNlVG89IjQ3NTczIiB4c2k6dHlwZT0ibGliOkFzc2VydGlvblR5cGUiPgo8c2FtbDpDb25kaXRpb25zICBOb3RCZWZvcmU9IjIwMTItMDQtMTJUMjI6MTE6NDJaIiBOb3RPbk9yQWZ0ZXI9IjIwMTItMDQtMTJUMjI6MTI6NDJaIiA+CjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb25Db25kaXRpb24+CjxzYW1sOkF1ZGllbmNlPmh0dHA6Ly9qb3Nzby0wMS5sb2NhbC5uZXR3b3JrOjgwODAvcG9ydGFsL2luaXRpYXRlc3NvbG9naW4vP1JlYWxtPWdnYXRlaW48L3NhbWw6QXVkaWVuY2U+Cjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uQ29uZGl0aW9uPgo8L3NhbWw6Q29uZGl0aW9ucz4KPHNhbWw6QXV0aGVudGljYXRpb25TdGF0ZW1lbnQgIEF1dGhlbnRpY2F0aW9uTWV0aG9kPSJBdXRoZW50aWNhdGlvblBsdWdpbiIgQXV0aGVudGljYXRpb25JbnN0YW50PSIyMDEyLTA0LTEyVDIyOjExOjQyWiIgUmVhdXRoZW50aWNhdGVPbk9yQWZ0ZXI9IjIwMTItMDQtMTJUMjI6MTI6NDJaIiB4c2k6dHlwZT0ibGliOkF1dGhlbnRpY2F0aW9uU3RhdGVtZW50VHlwZSI+PHNhbWw6U3ViamVjdCAgIHhzaTp0eXBlPSJsaWI6U3ViamVjdFR5cGUiPjxzYW1sOk5hbWVJZGVudGlmaWVyIE5hbWVRdWFsaWZpZXI9Imh0dHA6Ly9sb2NhbGhvc3Q6ODg4OC9vcGVuc3NvL2NkY3NlcnZsZXQiPkFRSUM1d00yTFk0U2ZjeUVQJTJGTjVsOUljQ3F5WXhtY01yUlBMVDY3azFEZUlDTmclM0QlNDBBQUpUU1FBQ01ERSUzRCUyMzwvc2FtbDpOYW1lSWRlbnRpZmllcj4KPHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbj4KPHNhbWw6Q29uZmlybWF0aW9uTWV0aG9kPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMDpjbTpiZWFyZXI8L3NhbWw6Q29uZmlybWF0aW9uTWV0aG9kPgo8L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj4KPGxpYjpJRFBQcm92aWRlZE5hbWVJZGVudGlmaWVyICBOYW1lUXVhbGlmaWVyPSJodHRwOi8vbG9jYWxob3N0Ojg4ODgvb3BlbnNzby9jZGNzZXJ2bGV0IiA+QVFJQzV3TTJMWTRTZmN5RVAlMkZONWw5SWNDcXlZeG1jTXJSUExUNjdrMURlSUNOZyUzRCU0MEFBSlRTUUFDTURFJTNEJTIzPC9saWI6SURQUHJvdmlkZWROYW1lSWRlbnRpZmllcj4KPC9zYW1sOlN1YmplY3Q+PHNhbWw6U3ViamVjdExvY2FsaXR5ICBJUEFkZHJlc3M9IjEyNy4wLjAuMSIgRE5TQWRkcmVzcz0ibG9jYWxob3N0IiAvPjxsaWI6QXV0aG5Db250ZXh0PjxsaWI6QXV0aG5Db250ZXh0Q2xhc3NSZWY+aHR0cDovL3d3dy5wcm9qZWN0bGliZXJ0eS5vcmcvc2NoZW1hcy9hdXRoY3R4L2NsYXNzZXMvUGFzc3dvcmQ8L2xpYjpBdXRobkNvbnRleHRDbGFzc1JlZj48bGliOkF1dGhuQ29udGV4dFN0YXRlbWVudFJlZj5odHRwOi8vd3d3LnByb2plY3RsaWJlcnR5Lm9yZy9zY2hlbWFzL2F1dGhjdHgvY2xhc3Nlcy9QYXNzd29yZDwvbGliOkF1dGhuQ29udGV4dFN0YXRlbWVudFJlZj48L2xpYjpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhlbnRpY2F0aW9uU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+CjxsaWI6UHJvdmlkZXJJRD5odHRwOi8vbG9jYWxob3N0Ojg4ODgvb3BlbnNzby9jZGNzZXJ2bGV0PC9saWI6UHJvdmlkZXJJRD48L2xpYjpBdXRoblJlc3BvbnNlPgo=";


   public void testParsingOpenAMMessage() throws Exception
   {
      parseMessageAndTest(TEST_MESSAGE_OPENAM, 124, "2012-04-12T07:46:15Z", "2012-04-12T07:47:15Z", "AQIC5wM2LY4SfcwAN6hjijOCPO1u7UurEn9DvqFXKzwFsi0.*AAJTSQACMDE.*");
   }

   public void testParsingOpenSSOMessage() throws Exception
   {
      parseMessageAndTest(TEST_MESSAGE_OPENSSO, 47573, "2012-04-12T22:11:42Z", "2012-04-12T22:12:42Z", "AQIC5wM2LY4SfcyEP/N5l9IcCqyYxmcMrRPLT67k1DeICNg=@AAJTSQACMDE=#");
   }


   private void parseMessageAndTest(String inputMessage, int expectedInResponseTo, String expectedNotBefore, String expectedNotOnOrAfter, String expectedToken) throws Exception
   {
      log.info("Test parsing message from CDCServlet");

      CDMessageParser messageParser = new CDMessageParser();
      String message = messageParser.decodeMessage(inputMessage);

      log.info("Message from CDCServlet is:");
      log.info(message);

      CDMessageContext messageContext = messageParser.parseMessage(inputMessage);

      assertTrue(messageContext.getSuccess());
      assertTrue(messageContext.getInResponseTo() == expectedInResponseTo);
      assertEquals(messageContext.getNotBefore(), expectedNotBefore);
      assertEquals(messageContext.getNotOnOrAfter(), expectedNotOnOrAfter);
      assertEquals(messageContext.getSsoToken(), expectedToken);
   }
}