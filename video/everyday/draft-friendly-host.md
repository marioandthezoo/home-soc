# Home SOC: A Friendly Look Around Your Home Network

*Draft: the friendly host. For everyday viewers. Written 2026-09-22 for the Stone & Sage dashboard with plain-language labels.*

**Logline.** A warm, funny neighbour walks everyday people through the four questions anyone with Wi-Fi eventually asks: Am I OK? What is that thing? What do I do? What if the internet dies? Home SOC answers each one in plain words, on a PC they already own.

**Length.** 1328 words of narration across 13 scenes, about **10.0 minutes** at the voice's measured 0.414 s a word (narrate.py) plus the marked pauses, before scene gaps. `[beat]` is about 0.6 s and `[beat 1.2]` is 1.2 s.

**Shape.** A cold-open joke, then four questions a real person asks: *Am I OK? What is that thing? What do I do? What if the internet dies?* Each technical idea is explained where the question needs it, with an analogy that is actually true. The close calls back to the opening joke.

| # | Scene | Explains | Words | Est. |
|---|---|---|---|---|
| 01 | Home SOC | — | 71 | 0:33 |
| 02 | What it is (and isn't) | privacy: it runs at home, nothing leaves your house, no account, free and open source (and it is not an antivirus) | 81 | 0:35 |
| 03 | Am I OK? | the safety score and 'Fix these first' | 98 | 0:44 |
| 04 | What's on my network? | your home network, and why it has far more devices than you think | 102 | 0:45 |
| 05 | What is that thing? | open ports and services (doors and windows on a house); Telnet and unencrypted logins | 131 | 0:58 |
| 06 | Which box is it? | Lens: point your phone at a mystery box and it tells you what it is | 106 | 0:47 |
| 07 | What do I do? | severity words and acting on a problem (the practical half of 'Fix these first') | 108 | 0:48 |
| 08 | Known flaws | known vulnerabilities, and 'a flaw exists' versus 'attackers are using this right now' (KEV), with the 30-day exploitation chance | 131 | 0:59 |
| 09 | Updates are the fix | updates and firmware as the fix | 106 | 0:46 |
| 10 | Who is it all talking to? | DNS and the Blocking feature (ads, trackers, known-bad sites; devices 'phoning home') | 124 | 0:54 |
| 11 | What if the internet dies? | what depends on what: if the router dies, what goes dark (reliance, never connections or traffic) | 127 | 0:57 |
| 12 | Is it getting better? | none (day-to-day use: Report, What happened, quiet notifications) | 41 | 0:17 |
| 13 | You can do this | privacy recap: free, open source, nothing leaves your house (no account is stated in scene 02); only scan networks you own or run | 102 | 0:47 |

## Production notes (read before capture)

These are places where the brief, the design proposal and the demo data do not line up yet. Each one
affects what can honestly be put on screen.

1. **Real brand on screen.** The demo router's problem title and evidence name a real router model and
   maker, and the Devices vendor column shows the maker too. The narration never names it. For scenes 08,
   09 and 11, use the redesign's plain title ("Your router has a known flaw that attackers are using") and
   keep the technical title, the vendor column and the evidence JSON out of frame, or crop or blur them. The
   villain camera is unbranded, which is on purpose.
2. **"Chance of attack" wording.** DESIGN.md §8.1 item 9 and §8.3 propose the label "94% chance of attack".
   That breaks the honesty rule: the figure is the chance the flaw is exploited somewhere in the next 30
   days, not the chance this household is attacked. The narration says it correctly. The on-screen label
   should read something like "Chance of exploitation, next 30 days: 94%". Fix the label before capture, or
   scene 08 shows words the narrator contradicts.
3. **Stale demo data.** Every render in `shots/` says "8d ago", and the Blocking cards read 0 with the
   resolver stopped, because the demo database is 8 days old. With the new status banner that would read
   "Home SOC last checked your network 8 days ago". Re-seed (`seed_demo.py`) so timestamps are fresh. The
   Blocking figures spoken in scene 10 (2,495 lookups, 789 blocked, 31.6%, 12 devices) and the camera's
   Talking-to figures (90 of 182 blocked, 49%) come from the freshly seeded capture used by the old video.
   Scene 10's closing limits beat is the one place the not-running banner belongs.
4. **Blast-radius click.** `map-blast-*.png` clicked "DNS resolution", not the router. Scene 11 needs the
   router click and its one-sentence answer.
5. **Healthy screen.** `healthy-overview-*-1920.png` is a demo copy edited to three Good to know items. It
   appears in scene 13 as "what you're aiming for". It is not presented as this household's result.
6. **Labels in the renders.** The renders show the palette with today's labels (Overview, Findings, DNS
   filter…). The script is written for the plain-language layer in DESIGN.md §8 with the labels from the
   brief: Home, Things to fix, Devices, What happened, Report, This computer, Blocking; Advanced: What
   depends on what, Known flaws, Checks, System health, Settings. DESIGN.md §8.1 item 5 still says "Web
   blocking" / "How things connect" / "Known software flaws". The narration uses the brief's names. Capture
   needs the §8 templates in place first.
7. **Lens** captures come from the existing phone pipeline (`phone.py`, the "shelf" scene render) with the
   Stone & Sage Lens tokens from `lens-tokens.md`. It is a viewfinder with a card, Chrome on Android, and a
   one-time certificate check, exactly as narrated.

## Honesty check

* Never says it stops hackers or catches viruses. Scene 02 says it is not an antivirus, scene 09 says Windows' antivirus did the catching, and scene 13 says "It won't make you hacker-proof. Nothing will."
* The map shows reliance, never traffic: "a line means 'relies on', not 'is chatting with'" (scene 11).
* The 30-day figure is "somewhere in the world", explicitly "Not the chance you get attacked" (scene 08).
* The version match is "A strong clue, not proof" (scene 08).
* Home SOC "knocks and reads the sign", and "doesn't try the handle": no exploitation (scene 05).
* Lens: Chrome on Android, a one-time certificate trust step, "a viewfinder with a card, not floating 3D labels" (scene 06).
* Blocking limits: "it only works while the PC is awake", and a device with its own private phone book skips it (scene 10).
* Only networks you own or run (scene 13); nothing leaves the house, no account, free and open source (scene 02, repeated in 13).
* The camera "phoning home" is only what its lookups show; Home SOC "never says what about" because it cannot see content.
* No real brand is called insecure; no politics, no stereotypes; the jokes land on gadgets, jargon, the printer and the tech world's names.

---

## 01-cold-open: Home SOC

**Purpose.** Open cold on a joke the viewer recognises from their own house, then promise what they will get.

**Explains.** none

**On screen.** Illustrated slide, no dashboard yet. A bathroom shelf in the Stone & Sage palette: an electric toothbrush on its charger with a small speech bubble, 'Update available: v4.2'. On 'I got to eleven' a hand-drawn tally counts up to 11 beside it. On 'this one's for you' the shelf zooms out into a cut-away house with small device icons glowing in every room. Title card 'Home SOC' on the last line.

**Narration.**

> A confession. [beat] Last week I counted every device in my house that connects to the internet. I got to eleven, felt rather pleased with myself, [beat] and then my toothbrush asked me to install an update. [beat 1.2] My toothbrush. Has software. [beat] It has never once asked how my day was. [beat 1.2] If your house has quietly filled up with gadgets that are chattier than they look, this one's for you. Let's meet Home SOC.

**Jokes in this scene.**

- Counting your devices, getting to eleven, then the toothbrush asks for an update.
- 'My toothbrush. Has software. [beat] It has never once asked how my day was.'
- Gadgets 'chattier than they look' (sets up the phoning-home scene).

---

## 02-what-it-is: What it is (and isn't)

**Purpose.** Say what Home SOC is and is not, and why an everyday person would want it, before any screen gets busy.

**Explains.** privacy: it runs at home, nothing leaves your house, no account, free and open source (and it is not an antivirus)

**On screen.** Illustrated slide on 'dark room of screens': a moody control room with a wall of monitors and one abandoned mug. On 'the home version' cut to a single PC on a desk in a sunny corner with a plant, then to the Home page of the Stone & Sage dashboard at rest: brand 'Home SOC' with the subtitle 'Home network safety', the everyday sidebar (Home, Things to fix, Devices, What happened, Report, This computer, Blocking, then the Advanced divider). Three plain captions stack as they are spoken: 'Free and open source', 'Runs in your house. No account. Nothing leaves.', 'Not an antivirus. Windows keeps that job.'

**Narration.**

> Big companies have a Security Operations Centre, a SOC: a dark room of screens and cold coffee. [beat] This is the home version. One PC you already own. Coffee optional. [beat 1.2] It's free and open source. It runs entirely in your house: no account, no cloud, and nothing leaves your home. [beat] It isn't an antivirus. Windows' own antivirus keeps that job. Home SOC is the friend who walks round checking the windows are shut, and tells you, in plain English, which ones aren't.

**Jokes in this scene.**

- A company SOC: 'a dark room of screens and cold coffee'.
- 'This is the home version. One PC you already own. Coffee optional.'
- 'The friend who walks round checking the windows are shut.'

---

## 03-am-i-ok: Am I OK?

**Purpose.** Answer 'Am I OK?' from the Home page: the one-sentence status, the safety score, the trend and Fix these first.

**Explains.** the safety score and 'Fix these first'

**On screen.** Home page. (1) Zoom to the status banner: 'Your network needs attention: two things should be fixed today, and six more this week.' (2) The 'How safe is your network?' gauge: 10, 'Needs work', grade F in brick red; topbar chip 'Safety 10/100 · Needs work'. (3) Let the sparkline and its caption 'Getting better: up from 5 a month ago' stay in frame (not narrated). (4) Scroll to the 'Fix these first' card and point at the '+4 points' pill on the first row. (5) Hold on the first row's plain title: the Telnet problem on the unnamed camera.

**Narration.**

> First question: am I OK? The Home page answers in a sentence: your network needs attention. Two things to fix today, six more this week. [beat] Safety score: ten out of a hundred. Grade F. [beat 1.2] Nobody likes an F. But this is the useful kind, with the answers attached. [beat] One really serious problem holds the whole score down. A spotless house with the front door wide open is not a safe house. [beat] Below that: Fix these first. The worst problems, and the points each fix wins back. [beat] Top of the list: a camera. [beat] Oh, we'll get to that camera.

**Jokes in this scene.**

- 'Nobody likes an F. But this is the useful kind, with the answers attached.'
- A spotless house with the front door wide open (makes the score ceiling memorable).
- 'Top of the list: a camera. [beat] Oh, we'll get to that camera.'

---

## 04-whats-on-my-network: What's on my network?

**Purpose.** Explain the home network and the router, and land the surprise that there are far more devices than you think.

**Explains.** your home network, and why it has far more devices than you think

**On screen.** Illustrated slide: a block of flats with one front door marked 'router'; each flat carries a number, and letters go in and out only through that door. Then Devices with the default five columns (Device, Kind, Online, Things to fix, Known) and the topbar chip '17 of 18 devices online'. Scroll slowly as the devices are named; pause on 'Nintendo Switch: Not connected'. On 'Seventeen, the family recognised' point at the Known column ('Yes, it's ours' / 'Not sure'). End with the cursor on the row that sorts first because it is unnamed and untrusted: 'Unnamed camera (192.168.1.142)', Not sure.

**Narration.**

> But what's actually on my network? Picture a block of flats. Your router is the front door: it gives every gadget a flat number, called an IP address, and everything to or from the internet goes through it. [beat] Ask this family how many devices they own: about six. [beat 1.2] Home SOC found eighteen. Phones, laptops, the TV, speakers, the printer, the doorbell, a plug for a lamp, and a plug for a heater, because apparently heaters need Wi-Fi now. [beat] Plus a Nintendo Switch, offline, so probably down the back of the sofa. [beat] Seventeen, the family recognised straight away. [beat] And then there's this one.

**Jokes in this scene.**

- 'Ask this family how many devices they own: about six.' [beat 1.2] 'Home SOC found eighteen.'
- 'A plug for a heater, because apparently heaters need Wi-Fi now.'
- The Switch is offline, 'so probably down the back of the sofa.'

---

## 05-what-is-that-thing: What is that thing?

**Purpose.** Meet the villain and use it to teach open ports, services, Telnet and the UPnP hole, with a true doors-and-windows analogy.

**Explains.** open ports and services (doors and windows on a house); Telnet and unencrypted logins

**On screen.** Open the unnamed camera's device page: the 'About this device' card shows no name, no vendor, kind 'camera'. Illustrated insert on 'think of every device as a house': a simple house with numbered doors and windows and a figure behind one door holding a sign. Back on the device page, the 'Open doors on this device' table with four rows; highlight door 23, Telnet. On 'postcard', an illustrated postcard slides in with 'username: admin / password: ••••••' on the back. On UPnP, cut to Things to fix and highlight the camera's 'Fix this week' row about the router door opened to the internet (technical title: 'UPnP port mapping: WAN 8443 -> 192.168.1.142:80').

**Narration.**

> No name. An address ending in one forty-two, and a best guess: camera. [beat] Nobody remembers buying it. [beat] Nobody ever does. [beat 1.2] Think of every device as a house. Its numbered doors are called ports, and behind some, a program called a service waits for a knock. The printer keeps a door open for print jobs. Home SOC knocks, reads the sign on the door, and writes it down. It doesn't try the handle. [beat] Here, door twenty-three says Telnet: a remote login from 1969, the year of the moon landing, and it has aged considerably worse. [beat] It sends your password unscrambled, like a postcard anyone can read. [beat] The camera also asked the router to open a door straight to the internet. The feature is called UPnP, and routers, bless them, usually say yes.

**Jokes in this scene.**

- 'Nobody remembers buying it. [beat] Nobody ever does.'
- Home SOC 'knocks, reads the sign on the door, and writes it down. It doesn't try the handle.'
- Telnet is from 1969, 'the year of the moon landing, and it has aged considerably worse.'
- 'Routers, bless them, usually say yes.'

---

## 06-which-box: Which box is it?

**Purpose.** Answer 'Which box is it?' in the physical world with Lens, and be straight about its limits.

**Explains.** Lens: point your phone at a mystery box and it tells you what it is

**On screen.** The illustrated hallway shelf with four identical white boxes (the existing 'shelf' scene render; build/scene_camera.png for the close-up of the camera with its Home SOC sticker). Then the phone: the Lens viewfinder over the shelf, the reticle corners flashing on the sticker, and the information card rising: 'Unbranded camera', online, not trusted, 'six problems, one of them fix-now', then the Problems section with its numbered steps. On the certificate line, cut to the desktop pairing screen with its security fingerprint and pairing QR. On the last line, a tongue-in-cheek insert: a sci-fi HUD with floating 3D labels gets a big 'No' stamp, then the real viewfinder-and-card returns.

**Narration.**

> Practical problem: you're in the hallway, facing four identical white boxes. [beat 1.2] Technology has many gifts. Labelling is not one of them. [beat] So there's Lens. Point your phone at a box: it reads the barcode already on it, or a sticker Home SOC prints, and up comes a card. Unbranded camera, six problems, one fix-now, with the steps. [beat] Honest details: it needs Chrome on Android, and the first time, your phone complains loudly about a certificate. That's a one-time trust step: check a short code matches on both screens. [beat] It's a viewfinder with a card, not floating 3D labels. [beat] A home network tool, not a superhero suit.

**Jokes in this scene.**

- 'Four identical white boxes.' [beat 1.2] 'Technology has many gifts. Labelling is not one of them.'
- 'Your phone complains loudly about a certificate.'
- 'It's a viewfinder with a card, not floating 3D labels. [beat] A home network tool, not a superhero suit.'

---

## 07-what-do-i-do: What do I do?

**Purpose.** Answer 'What do I do?': the everyday severity words, reading a problem, and the safe action buttons.

**Explains.** severity words and acting on a problem (the practical half of 'Fix these first')

**On screen.** Things to fix, tab 'Needs attention (33)'. Point at the severity badges with their action words: Fix now (brick), Fix this week (terracotta), Worth fixing (ochre), When you have time (moss), Good to know (slate blue). On 'a fever to a robot', a brief insert shows Critical / High / Medium / Low / Info in a stiff monospace font, dissolving into the plain words. Open the Telnet row: the expanded detail with its sage edge reading What's wrong, Why it matters, How to fix it, then the buttons 'I've fixed it', 'I've seen this', 'Ignore this from now on…', and the closed 'Technical details' disclosure.

**Narration.**

> So, what do I do? Security people rank problems Critical, High, Medium, Low and Info, [beat] which is how you'd describe a fever to a robot. [beat] Things to fix just says what it means: Fix now. Fix this week. Worth fixing. When you have time. Good to know. [beat] The Telnet problem says what's wrong, why it matters, and how to fix it: switch Telnet off in the camera's settings, or unplug it and see who complains. [beat 1.2] Somebody always complains. That's how you find out whose it is. [beat] Press I've fixed it: Home SOC takes your word for it, then checks on the next scan anyway. Like a good parent.

**Jokes in this scene.**

- Critical, High, Medium, Low and Info: 'which is how you'd describe a fever to a robot.'
- 'Unplug it and see who complains.' [beat 1.2] 'Somebody always complains. That's how you find out whose it is.'
- 'I've fixed it': Home SOC takes your word for it, then checks anyway. 'Like a good parent.'

---

## 08-known-flaws: Known flaws

**Purpose.** Explain known flaws, the difference KEV makes, and what the 30-day chance figure does and does not mean.

**Explains.** known vulnerabilities, and 'a flaw exists' versus 'attackers are using this right now' (KEV), with the 30-day exploitation chance

**On screen.** Illustrated slide: a front-door lock with a small tag 'could be picked, in theory'; on the burglar line a friendly police officer at the door holding a flyer 'Seen in your area: this trick, this lock'. Then Advanced > Known flaws: plain 'What' column first; set 'Attackers using it?' to Yes and one row remains, on the Home router, with its known-exploited badge. Point at 'Chance of exploitation, next 30 days: 94%'. Clear the filter and point at the camera's web-server row, about 4%. Keep the router's brand and model out of frame (see production notes).

**Narration.**

> The other fix-now problem is the router. Home SOC matches software versions against public lists of known flaws. A strong clue, not proof. [beat] And every lock can be picked, in theory. What matters is whether attackers are using it right now: the police knocking to say local burglars use this exact trick on this exact lock. [beat] That list is KEV, from CISA, the US cybersecurity agency. [beat] Yes, it's pronounced Kev. [beat] The tech world names things like it's late for a bus. [beat 1.2] Your router is on it. [beat] Then a percentage: the chance this flaw gets exploited somewhere in the world in the next thirty days. Router: ninety-four. Not the chance you get attacked: it's how busy the trick is. The camera's flaw: about four. [beat] Only one is fashionable with burglars this month.

**Jokes in this scene.**

- 'Every lock can be picked, in theory.'
- The police knocking to say burglars round here are using this exact trick on this exact lock.
- 'Yes, it's pronounced Kev.' [beat] 'The tech world names things like it's late for a bus.'
- 'Only one is fashionable with burglars this month.'

---

## 09-updates-are-the-fix: Updates are the fix

**Purpose.** Make updates and firmware feel like the ordinary, doable fix, and show This computer as the one machine Home SOC sees from inside.

**Explains.** updates and firmware as the fix

**On screen.** Things to fix, the router's known-exploited problem expanded to 'How to fix this' with its numbered steps (update the firmware; if no fix exists, switch the service off or replace the device). Illustrated insert on 'posting you a better lock': a parcel with a shiny new lock on the doormat, unopened. Then This computer: 'Windows antivirus: On', 'Real-time protection: On', the updates card with three updates waiting. Point at the threat line 'invoice_2026_08.pdf.exe (quarantined)'. On 'PDF costume', a small illustration of a document icon wearing a slightly-too-small paper disguise over a gear.

**Narration.**

> The fix is wonderfully boring: updates. The software inside a gadget is called firmware. An update is the lock company posting you a better lock, free. You just have to open the post. [beat] The router's steps say: install the latest firmware, from a menu nobody has opened since the day it was plugged in. [beat] This computer checks the PC itself: antivirus on, three updates waiting. Last month the antivirus caught invoice dot P D F dot E X E. [beat] That's not a PDF. It's a program in a PDF costume. [beat] Windows locked it away. Home SOC's job is to tell you if it's ever switched off.

**Jokes in this scene.**

- 'The lock company posting you a better lock, free. You just have to open the post.'
- The update button lives 'in a menu nobody has opened since the day it was plugged in.'
- 'invoice dot P D F dot E X E. That's not a PDF. It's a program in a PDF costume.'

---

## 10-who-is-it-talking-to: Who is it all talking to?

**Purpose.** Explain DNS as the internet's phone book, what Blocking does, and devices phoning home, with its two honest limits.

**Explains.** DNS and the Blocking feature (ads, trackers, known-bad sites; devices 'phoning home')

**On screen.** Illustrated slide: a chunky old phone book open at 'Where does this website live?', a device icon asking and a number coming back. Then Blocking with freshly seeded data: 'Websites looked up today 2,495', 'Blocked today 789' (about a third), 'Devices using it 12', 'Status: Running', and the hourly chart. Point at 'Top blocked domains' with reasons in words. Then the camera's Lens card, 'Talking to' section: '90 of 182 lookups blocked, 49%', and the 'Most contacted' list led by its maker's servers. On the limits, the not-running banner: 'Web blocking is switched on but not running, so nothing is being filtered right now.'

**Narration.**

> Next: who is all this stuff talking to? Before a device goes anywhere online, it looks it up in DNS: the internet's phone book. [beat] Change one router setting and Home SOC becomes your house's phone book. Then Blocking refuses to look up ads, trackers, scams and malware. [beat] In one day here: two and a half thousand lookups. [beat] You didn't do that. The gadgets did. [beat] A third were blocked. [beat] Our camera? Half its lookups blocked, and most of what it asks for is its maker's servers. That's phoning home: a homesick kid at camp who checks in all day and never says what about. [beat] Two limits: it only works while the PC is awake, and a device with its own private phone book skips it.

**Jokes in this scene.**

- 'Two and a half thousand lookups.' [beat] 'You didn't do that. The gadgets did.'
- Phoning home: 'a homesick kid at camp who checks in all day and never says what about.'

---

## 11-what-if-the-internet-dies: What if the internet dies?

**Purpose.** Answer 'What if the internet dies?' with What depends on what, and make its honesty (reliance, not traffic) part of the appeal.

**Explains.** what depends on what: if the router dies, what goes dark (reliance, never connections or traffic)

**On screen.** Advanced > What depends on what, columns The internet / Your router / Shared services / Your devices. Click the Home router: affected nodes and lines stay bold, the rest dims, and the side panel answers in one sentence: 'If the Home router fails, 17 devices lose their internet connection. They stay on the local network and can still reach each other.' On the printer line, a tiny cut to the Epson printer node, lit. Then point at the calm note card at the top, 'This is not a traffic diagram…', and at the 'How sure are we?' legend (Seen / Worked out / Assumed). End on the side panel's 'Most load-bearing right now: Home router'. (The existing map-blast render clicked DNS resolution; capture the router click for this scene.)

**Narration.**

> Last question: what if the internet dies? [beat] Or the router does, twenty minutes before something important. [beat] Open What depends on what, tap the router, and one sentence answers: seventeen devices lose the internet, but they stay on the home network and can still reach each other. [beat] So the laptops can still print. [beat 1.2] Whether the printer agrees is between you and the printer. [beat] The page says it plainly: this is not a traffic diagram. Home SOC can't see what devices say to each other, so a line means "relies on", not "is chatting with", and shows how sure Home SOC is. Where it doesn't know, it draws nothing. [beat] The most load-bearing thing in the house? The router with the flaw attackers are using. [beat 1.2] Maybe do that update first.

**Jokes in this scene.**

- The router will die 'twenty minutes before something important.'
- 'So the laptops can still print. [beat 1.2] Whether the printer agrees is between you and the printer.'
- 'Where it doesn't know, it draws nothing.'
- 'Maybe do that update first.'

---

## 12-is-it-getting-better: Is it getting better?

**Purpose.** Show that it is working over time (Report, What happened) and that it mostly runs itself without nagging.

**Explains.** none (day-to-day use: Report, What happened, quiet notifications)

**On screen.** Report ('Your safety report'): the plain KPI row (48 found, 12 fixed, 33 still to fix) and the 'Is it getting better?' chart climbing from 5 to 10. On 'the fridge door', a small illustration of the printed report held up by a fridge magnet. Then What happened: serif day headers and plain rows such as a known-malicious site blocked and a device joining. On notifications, one phone notification slides in.

**Narration.**

> Report is the page for the fridge door: forty-eight found, twelve fixed, score creeping up. What happened is the diary. And it only pipes up when something serious turns up. One notification. Not fifty. [beat] A smoke alarm, not a car alarm.

**Jokes in this scene.**

- Report is 'the page for the fridge door'.
- 'One notification. Not fifty.' [beat] 'A smoke alarm, not a car alarm.'

---

## 13-close: You can do this

**Purpose.** Sum up, restate the privacy promise and the honest limits, leave the viewer feeling capable, and land the callback.

**Explains.** privacy recap: free, open source, nothing leaves your house (no account is stated in scene 02); only scan networks you own or run

**On screen.** Home page, then a slow dissolve to the healthy Home page at 1920 (100, grade A, sage gauge, 'Good', the calm banner 'Your network looks healthy', quiet zero-count badges), captioned 'What you're aiming for'. On 'your neighbour's', an illustration of two front doors side by side, one with a 'yours' mat. Final shot: the bathroom shelf from the cold open, the toothbrush's bubble now reading 'Update installed', then the end card: 'Home SOC · free and open source · runs at home'.

**Narration.**

> So: Home SOC finds what's on your network, says what matters, and walks you through the fix. Free, open source, and nothing leaves your house. It won't make you hacker-proof. Nothing will. It turns a vague unease into a short to-do list. [beat] One rule: only use it on networks you own or run. Knocking on your own doors is housekeeping. [beat] Knocking on your neighbour's is a different conversation. [beat 1.2] Work down the list and you end up here: a calm green dial. You can do this. [beat] And if your toothbrush asks for an update, [beat] say yes. [beat 1.2] It still won't ask about your day.

**Jokes in this scene.**

- 'Knocking on your own doors is housekeeping. [beat] Knocking on your neighbour's is a different conversation.'
- Callback: 'And if your toothbrush asks for an update, [beat] say yes.'
- 'It still won't ask about your day.'

---
