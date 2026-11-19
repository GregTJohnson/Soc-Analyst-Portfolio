Oct. 13, 2026

**Summary**

The reported email is a malicious, most likely credential phishing
attempt, sent from a throwaway Microsoft tenant through Google's mail
relay. It failed sender checks, hides a tracking pixel, and has a log in
request asking to “Verify Account Here” with a “Valid Until 11:59 p.m.
EST Tonight NON-TRANSFERABLE” deadline. No attachment detected.

**Case Details**

<table>
<tbody>
<tr class="odd">
<td>Field</td>
<td>Value</td>
</tr>
<tr class="even">
<td>Playbook used</td>
<td>Phishing Email Triage</td>
</tr>
<tr class="odd">
<td>Source</td>
<td><p>Sample-10044</p>
<p><a href="https://github.com/rf-peixoto/phishing_pot/tree/main/email"><span class="underline">https://github.com/rf-peixoto/phishing_pot/tree/main/email</span></a></p></td>
</tr>
<tr class="even">
<td>Message ID</td>
<td><strong>&lt;<a href="mailto:CAOMrsEFgQ0wOsDxdOOGDH=Rn5FHCAJGDtT5YuC3JqPwgFM2YnQ@mail.gmail.com"><span class="underline">CAOMrsEFgQ0wOsDxdOOGDH=Rn5FHCAJGDtT5YuC3JqPwgFM2YnQ@mail.gmail.com</span></a>&gt;</strong></td>
</tr>
<tr class="odd">
<td>Received by Microsoft</td>
<td>Tue, 7 Jul 2026 21:15:28 +0000</td>
</tr>
<tr class="even">
<td>Sent (Date header)</td>
<td>Tue, 7 Jul 2026 14:15:22 -0700</td>
</tr>
<tr class="odd">
<td>Receiving system</td>
<td>Microsoft Outlook/Exchange Online</td>
</tr>
<tr class="even">
<td>Subject</td>
<td>Your Turn to Play</td>
</tr>
<tr class="odd">
<td>Tools used</td>
<td>Text editor, Message Header Analyzer, VirustTotal, Uriscan</td>
</tr>
</tbody>
</table>

**Findings**

|                      |                                                                                                                                                                                                                                                              |                                                                               |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| Check                | Result                                                                                                                                                                                                                                                       | Evidence (field, line)                                                        |
| Sender               | **Alex\[ . \]thompson1@gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com**; **Return-Path** is the same address                                                                                                                                             | (line 101), Return-Path (line 109)                                            |
| Display name         | Welcome, Partner\!                                                                                                                                                                                                                                           | (line 101)                                                                    |
| SPF                  | Fail: the sending IP is not permitted for the sender’s domain                                                                                                                                                                                                | **Authentication-Results** (line 28), **Received-SPF** (line 33)              |
| DKIM                 | Pass, but the signing domain **(d=)** is a Google relay domain **(…gappssmtp\[ . \]com)**, not the From domain, so it does not align                                                                                                                         | **Authentication-Results** (line 29), **DKIM-Signature** (lines 64,65)        |
| DMARC                | None                                                                                                                                                                                                                                                         | **Authentication-Results** (line 31)                                          |
| Source               | **[<span class="underline">mail-lf1-f45.google</span>](http://mail-lf1-f45.google)\[ . \]com (209\[ . \]85\[ . \]167\[ . \]45)**, a Google server, message created through the Gmail. API                                                                    | **Received** (line 37, 42) **X-Sender-IP** (line 125)                         |
| Microsoft spam score | SCL 5                                                                                                                                                                                                                                                        | **X-MS-Exchange-Organization-SCL** (line 129)                                 |
| Content              | \*FINAL MESSAGE: Payout Verification\*A $1,000,000.00 PAYOUT is ready to be addressed in your name. Please confirm your details below as soon as possible to ensure secure delivery.                                                                         | (Line 3329 to 3355)                                                           |
| Links                | Every link and clickable image goes to **[<span class="underline">hxxps://woondsplay\[ . \]com/rd/index.php?</span>](hxxps://woondsplay%5B.%5Dcom/rd/index.php?)...** (parameters shortened), a redirect path on a domain that is not the advertised brand's | (Lines 3324, 3338, 3343, 3347, 3351,3354, 6614, 6585, 6606, 6616, 6626, 6646) |
| Other images         | [<span class="underline">hxxps://i.imgur\[</span>](hxxps://i.imgur%5B) . \]com                                                                                                                                                                               | **\<img src=** (line 6649)                                                    |
| Tracking             | 1x1 hidden image at **[<span class="underline">hxxps://woondsplay\[</span>](hxxps://woondsplay%5B) . \]com/track/…** with display: none                                                                                                                      | **\<img src=** (line 6662)                                                    |
| Junk padding         | Thousands of lines of random text in both parts; evasion, not content                                                                                                                                                                                        | (Lines 209 to 3320) HTML (lines 3364 to 6475                                  |
| Attachements         | None                                                                                                                                                                                                                                                         | Content-Type (line 206)                                                       |

### 

**Indicators (defanged)**

|                          |                                                                             |                                           |
| ------------------------ | --------------------------------------------------------------------------- | ----------------------------------------- |
| Type                     | Value                                                                       | Use                                       |
| Sender domain            | **gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com**                      | Block and search mail logs                |
| Sender address           | **Alex\[ . \]thompson1@gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com** | Block and search mail logs                |
| Link and tracking domain | **woondsplay\[ . \]com**                                                    | Block at proxy and DNS; search for visits |
| Image host               | **I\[ . \]imgur\[ . \]com**                                                 | Watch only; may be benign                 |
| Sending IP               | **209\[ . \]85\[ . \]167\[ . \]45**                                         | Do not block: Google server               |

### 

**Response**

Search the mail system for other messages from this sender or with
**woondsplay\[.\]com** links.

Ask whether anyone clicked.

If nobody clicked: delete the message from mailboxes and block the
sender, the sender domain, and **woondsplay\[.\]com**.

If someone clicked: ask what they did on the site, then reset
credentials if they entered any, enforce MFA, review logs for activity

Escalate to Tier 2 only if someone clicked and entered credentials, or
the same message reached many recipients.

e.g. Same sender infrastructure as the “Your reward is available” case.”

**Verdict**

**Alert:** reported email “Your Turn to Play”, 7 Jul 2026, from an
[<span class="underline">onmicrosoft.com</span>](http://onmicrosoft.com)
sender

**What I checked:** sender, authentication, sending IP, spam score, body
text, links, hidden content, attachments.

**Findings:** SPF failed and DKIM doesn’t align with the From domain. It
was sent through Google’s relay. All links go to woondsplay\[ . \]com
with “Verify Account” and a fake coupon. It has junk padding and a
tracking pixel.

**Verdict:** malicious, most likely credential phishing. Reason: it asks
to “verify my account” through links to an unrelated domain.

**What would change it:** the link domain proving to be legitimate and
having long established service.

**Not verified:** the domain’s reputation. Domain’s registration date is
2025-01-24
