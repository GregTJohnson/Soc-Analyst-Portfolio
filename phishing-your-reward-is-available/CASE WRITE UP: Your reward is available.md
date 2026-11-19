Oct 12, 2026

**Summary**

The reported email is a bulk promotion for an online casino, sent from a
throwaway Microsoft tenant through Google<span dir="rtl">’</span>s mail
relay. It failed sender checks, hides a tracking pixel, and sends every
link to a domain that is not the advertised
brand<span dir="rtl">’</span>s. It has no attachment and no login
request, so it is not confirmed credential phishing. The landing page
was not checked.

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
<td><p>Sample-10048</p>
<p><a href="https://github.com/rf-peixoto/phishing_pot/tree/main/email"><span class="underline">https://github.com/rf-peixoto/phishing_pot/tree/main/email</span></a></p></td>
</tr>
<tr class="even">
<td>Message ID</td>
<td><strong><a href="mailto:CAEj+MiOi8pvM3SV6nG1NPy36j+HuUeX3GDfsMXefkSSRjrEnfg@mail.gmail.com"><span class="underline">CAEj+MiOi8pvM3SV6nG1NPy36j+HuUeX3GDfsMXefkSSRjrEnfg@mail.gmail.com</span></a></strong> (line 105)</td>
</tr>
<tr class="odd">
<td>Received by Microsoft</td>
<td>Tue, 7 Jul 2026 19:18:50 +0000 (line 2)</td>
</tr>
<tr class="even">
<td>Sent (Date header)</td>
<td>Tue, 7 Jul 2026 14:18:45 -0500 (line 103)</td>
</tr>
<tr class="odd">
<td>Receiving system</td>
<td>Microsoft Outlook/Exchange Online (lines 1,18, 23)</td>
</tr>
<tr class="even">
<td>Subject</td>
<td>Your reward is available (four gift emoji); base64-encoded on 106</td>
</tr>
<tr class="odd">
<td>Tools used</td>
<td>Text editor, Message Header Analyzer, VirustTotal, base64 decoding</td>
</tr>
</tbody>
</table>

**Findings**

|                      |                                                                                                                                                                                                                                                              |                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Check                | Result                                                                                                                                                                                                                                                       | Evidence (field, line)                                                     |
| Sender               | **ellis.thomas@gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com**, a free Microsoft default domain; **Return-Path** is the same address                                                                                                                    | From (line 102), **Return-Path** (line 110)                                |
| Display name         | Base64-encoded; decodes to "your bonus" + money-bag emoji + "rodrigo-f-p" + money-bag emoji. It does not match the address.                                                                                                                                  | From (Line 102)                                                            |
| SPF                  | Fail: the sending IP is not permitted for the sender's domain                                                                                                                                                                                                | **Authentication-Results** (line 28), **Received-SPF** (line 33)           |
| DKIM                 | Pass, but the signing domain **(d=)** is a Google relay domain **(…gappssmtp\[ . \]com)**, not the From domain, so it does not align                                                                                                                         | **Authentication-Results** (line 31), **DKIM-Signature** (lines 64 and 65) |
| DMARC                | None (the domain publishes no policy)                                                                                                                                                                                                                        | **Authentication-Results** (line 31)                                       |
| Source               | **[<span class="underline">mail-ed1-f44.google</span>](http://mail-ed1-f44.google)\[ . \]com (209\[ . \]85\[ . \]208\[ . \]44)**, a Google server; message created through the Gmail API. The IP is not useful as an indicator.                              | **Received** (lines 37, 42, 98, 100), **X-Sender-IP** (line 126)           |
| Microsoft spam score | SCL 8 (high range). The message was still delivered;                                                                                                                                                                                                         | **X-MS-Exchange-Organization-SCL** (line 130)                              |
| Content              | Casino promotion: "100% up to $750 + 200 FS + 1 Bonus Crab", "New Players Only", "first deposits". No login or verify request.                                                                                                                               | Plain-text part (lines 3339 to 3376); HTML part (lines 6534 to 6721)       |
| Links                | Every link and clickable image goes to **[<span class="underline">hxxps://woondsplay\[ . \]com/rd/index.php?</span>](hxxps://woondsplay%5B.%5Dcom/rd/index.php?)...** (parameters shortened), a redirect path on a domain that is not the advertised brand's | \<a href= (lines 3344, 3353, 3378, 3389, 6552, 6624, 6738, 6791)           |
| Other images         | Brand logo from **imgprom\[ . \]com**; image from I**.imgur\[ . \]com**                                                                                                                                                                                      | **\<img src=** (lines 6555, 6794)                                          |
| Tracking             | A 1x1 hidden image at **[<span class="underline">hxxps://woondsplay\[ . \]com/track/</span>](hxxps://woondsplay%5B.%5Dcom/track/)...** with **display:none** and a unique recipient ID in the URL                                                            | **\<img src=** (line 6807)                                                 |
| Junk padding         | Thousands of lines of random text in both parts; evasion, not content                                                                                                                                                                                        | Plain-text part (lines 225 to 3336); HTML part (lines 3399 to 6510)        |
| Attachements         | None. The message is **multipart/alternative** with only a plain-text part and an HTML part.                                                                                                                                                                 | **Content-Type** (lines 108, 222, 3393)                                    |

### 

**Indicators (defanged)**

|                          |                                                                           |                                           |
| ------------------------ | ------------------------------------------------------------------------- | ----------------------------------------- |
| Type                     | Value                                                                     | Use                                       |
| Sender domain            | **gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com**                    | Block and search mail logs                |
| Sender address           | **ellis\[ . \]thomas@gbnfrostbornwarriors02\[ . \]onmicrosoft\[ . \]com** | Block and search mail logs                |
| Link and tracking domain | **woondsplay\[ . \]com**                                                  | Block at proxy and DNS; search for visits |
| Image host               | **imgprom\[ . \]com**                                                     | Watch only; may be benign                 |
| Sending IP               | **209\[ . \]85\[ . \]208\[ . \]44**                                       | Do not block: Google server               |

### 

**Response**

Search the mail system for other messages from this sender or with
**woondsplay\[.\]com** links.

Ask whether anyone clicked.

If nobody clicked: delete the message from mailboxes and block the
sender, the sender domain, and **woondsplay\[.\]com**.

If someone clicked: ask what they did on the site (typed a password,
entered payment details), check proxy or DNS logs for the visit, reset
credentials if any were entered, and run an endpoint scan as a
precaution.

Escalate to Tier 2 only if someone clicked and entered data, or the same
message reached many recipients.

**Verdict**

**Alert:** reported email "Your reward is available," sent Tue, 7 Jul
2026 14:18:45 -0500, from an **onmicrosoft.com** sender.

**What I checked:** sender and display name, authentication, sending IP,
spam score, body text, links, hidden content, attachments.

**Findings:** SPF failed and DKIM does not align with the From domain.
It was sent through Google's relay. The display name does not match the
address. All links go to **woondsplay\[.\]com**, a redirect domain that
is not the advertised brand's. It has junk padding and a hidden tracking
pixel. It has no attachment.

**Verdict:** deceptive bulk gambling promotion (spam/scam). Reason:
failed and misaligned sender checks, a throwaway sender with a
mismatched display name, evasion padding, a hidden tracking pixel, and
links to a domain that is not the brand's.

**What would change it:** **woondsplay\[.\]com** proving to be a
legitimate, long-established service used by the brand, or a landing
page that asks for a login (which would make it phishing).

**Not verified:** the domain's reputation checks are incomplete.
Domain’s registration date is 2025-01-24
