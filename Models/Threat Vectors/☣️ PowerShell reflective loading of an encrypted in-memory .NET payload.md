

# ☣️ PowerShell reflective loading of an encrypted in-memory .NET payload

🔥 **Criticality:High** ⚠️ : A High priority incident is likely to result in a demonstrable impact to public health or safety, national security, economic security, foreign relations, civil liberties, or public confidence. 

🚦 **TLP:CLEAR** ⚪ : Recipients can spread this to the world, there is no limit on disclosure.


🗡️ **ATT&CK Techniques** [T1620 : Reflective Code Loading](https://attack.mitre.org/techniques/T1620 'Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads Reflective loading involves allocating t'), [T1027.013 : Obfuscated Files or Information: Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013 'Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection Encrypting andor encoding file co'), [T1059.001 : Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001 'Adversaries may abuse PowerShell commands and scripts for execution PowerShell is a powerful interactive command-line interface and scripting environm')



---

`🔑 UUID : 72e77176-58de-4bd2-b5a2-d05db16b474f` **|** `🏷️ Version : 1` **|** `🗓️ Creation Date : 2026-07-21` **|** `🗓️ Last Modification : 2026-07-21` **|** `👩‍💻 Model author : Nicola&Claude` **|** `🧱 Schema Identifier : tvm::2.1`


## 👁️ Description

> ## Attack Flow
> The adversary embeds or stages a .NET assembly that has been compressed with GZip and then
> encrypted with a symmetric AES key. A PowerShell script reverses that chain entirely in
> memory: the ciphertext is decrypted through a .NET cryptography provider
> (`AesCryptoServiceProvider`, `RijndaelManaged`, or an equivalent `CreateDecryptor` call), the
> plaintext is decompressed through `GZipStream`, and the resulting byte array is handed to
> `[System.Reflection.Assembly]::Load()`. The assembly is mapped directly into the running
> PowerShell process and its entry point invoked, without the payload ever being committed to
> disk in executable form.
> 
> ## Purpose of the encoding chain
> The two transformation stages serve distinct evasive purposes. Encryption defeats static
> signature matching against the payload at rest and in transit, since the on-disk or on-wire
> artefact carries no recognisable PE structure. Compression reduces the size of the staged blob
> and further disturbs any byte patterns that survive encryption. Reflective loading then avoids
> the file-write and process-creation events that on-disk execution would generate, so
> controls oriented around file scanning and image loads see no new executable.
> 
> ## Detection surface and limitations
> Because the entire chain is expressed in script text, the behaviour is observable wherever
> PowerShell script block content is recorded. It is correspondingly fragile as a detection
> target: the API names are plain strings and can be split, concatenated, aliased, or resolved
> dynamically at runtime, and the whole script can itself be delivered as an encoded blob and
> executed via `Invoke-Expression`. Any detection built on literal API names should be treated
> as covering the unobfuscated case only. AMSI provides a partial independent view, as the
> deobfuscated buffer is submitted for scanning prior to execution.
> 
> ## Modelling provenance
> This vector was reverse-derived from an existing detection artefact — ref [a] — rather than
> from a threat intelligence report. No campaign, actor attribution, tooling family, or
> victimology is claimed, because none was available in the source. The technique mappings in
> ref [1] and ref [2] describe the general behaviour class. The `leverage` and `impact` values
> reflect the capability this vector confers — arbitrary in-memory code execution — and not any
> observed outcome, since the loaded payload is by definition unknown at the point of loading.
> 



## 🖥️ Terrain 

 > Requires the ability to execute PowerShell in the user's own security context; no
> administrative privilege is needed, as the assembly is loaded into the current process
> rather than injected elsewhere. PowerShell must operate in Full Language Mode — Constrained
> Language Mode, or WDAC/AppLocker in enforced allow-listing mode, blocks the .NET reflection
> calls this vector depends upon. The encrypted payload bytes and the symmetric key must
> already be reachable to the script, whether embedded in the script body, staged on disk, or
> retrieved over the network; this vector models the loading step only, not payload acquisition.
> 

---

## 🕸️ Relations



### 🌊 OpenTide Objects
🚫 No related OpenTide objects indexed.





---

## Model Data

#### **⛓️ Cyber Kill Chain**

 > Cyber attacks are typically phased progressions towards strategic objectives. The Unified Kill Chains provides insight into the tactics that hackers employ to attain these objectives. This provides a solid basis to develop (or realign) defensive strategies to raise cyber resilience.

 [`🏃🏽 Defense Evasion`](https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf) : Techniques an attacker may specifically use for evading detection or avoiding other defenses.

---

#### **💣 Severity**

 > The severity summarizes the overall danger of incident the vector will provoke, and is to be derived (WIP) from impact, leverage, and difficulty to execute.

 [`🧨 Moderate incident`](https://www.ncsc.gov.uk/news/new-cyber-attack-categorisation-system-improve-uk-response-incidents) : A cyber attack on a small organisation, or which poses a considerable risk to a medium-sized organisation, or preliminary indications of cyber activity against a large organisation or the government.

---

#### **🪄 Leverage acquisition**

 > Technical aftermath of the attack from the target perspective, differentiated from impact as it does not consider the value of the consequence, only what increased control the vector execution provides to the adversary.

  - [`📦 Software installation`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Software installation or code modification
 - [`🦠 Dwelling`](https://owasp.org/www-community/Threat_Modeling_Process#stride) : Active or passive extended presence in the target, which performs adversarial operations continuously.

---

#### **💥 Impact**

 > Analysis of the threat vector from the organizational perspective, in non technical term. This aims at putting a clear denomination on what the attacker will actually be able to act upon if the threat vector is realized.

  - [`🔓 Data Breach`](http://veriscommunity.net/enums.html#section-impact) : Non-public information has been accessed from the outside, and successfully extracted.
 - [`🛑 Business disruption`](http://veriscommunity.net/enums.html#section-impact) : Business disruption

---

#### **🎲 Vector Viability**

 > Described with estimative language (likelyhood probability), describes how likely the analyst believes the vector to actually be realized on the organization infrastructure. Estimative language describes quality and credibility of underlying sources, data, and methodologies based Intelligence Community Directive 203 (ICD 203) and JP 2-0, Joint Intelligence.

 [`🧐 Likely`](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf) : Probable (probably) - 55-80%

---





## 🌐 Threat Surface

- ` OS::Windows::Desktop` — Microsoft Windows desktop editions
- ` OS::Windows::Server` — Microsoft Windows Server editions

_No assets in the visibility configuration match this threat surface._


### 🔗 References



**🕊️ Publicly available resources**

- [_1_] https://attack.mitre.org/techniques/T1620/
- [_2_] https://attack.mitre.org/techniques/T1027/013/

**🏦 Private references**

- [_a_] DetectionsAI rule 45c170c3-7340-4b0c-8a97-2f3be327f857

[1]: https://attack.mitre.org/techniques/T1620/
[2]: https://attack.mitre.org/techniques/T1027/013/
[a]: DetectionsAI rule 45c170c3-7340-4b0c-8a97-2f3be327f857

---

#### 🏷️ Tags

#-, #-, #-, #
, #
, ##, ##, ##, ##, # , #🏷, #️, # , #T, #a, #g, #s, #
, #


