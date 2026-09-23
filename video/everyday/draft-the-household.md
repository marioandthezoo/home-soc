# Meet the Household: one week with Home SOC

*Home SOC everyday walkthrough, draft script. Angle: **Meet the Household**. Written 2026-09-22.*

> A family of four finds out they own eighteen gadgets, one of them a camera nobody remembers buying. Over one ordinary week, a calm new housemate called Home SOC counts the gadgets, spots the open doors, and helps the family fix things one at a time.

**Estimated narration:** about 9.9 minutes (1385 words at ~150 wpm, the measured rate of the technical film's voice (2,491 words in 993 s of audio), plus about 31 s of extra silence from the marked beats and 0.8 s per scene for lead-in and hand-over; a beat that lands on a sentence end is counted at 0.3 s extra because the voice already pauses there). `[beat]` is a pause of about 0.6 s; `[beat 1.2]` is 1.2 s.

**Audience:** everyday households, not IT people. **Tone:** warm and observational. The jokes are about the gadgets, the jargon and the printer, never the viewer.

**Target dashboard:** the Stone & Sage redesign with the plain-language layer (DESIGN.md §8). The navigation is Home, Things to fix, Devices, What happened, Report, This computer and Blocking. Under Advanced it is What depends on what, Known flaws, Checks, System health and Settings. The layout references point to the renders in `scratchpad/design/final/shots/`. Those renders still show the old labels, so the capture must be made after the plain-language layer ships.

## Cast

| character | who they are on screen |
|---|---|
| The family | Mum, Dad and Ellie (each has an iPhone), plus two MacBooks, a kitchen tablet and the Home PC |
| Home SOC | the calm new housemate who notices things, and lives on the Home PC |
| The printer | has opinions and a grudge; offers printing to the whole house, and nobody has been seen using it |
| The smart plugs | a lamp plug and a heater plug: small, eager, and on the internet |
| The TV | would like to tell someone what you watched |
| The Switch | offline, because it's a school night |
| The kitchen Echo | the newest arrival, already marked 'Yes, it's ours' (seen on screen, not narrated) |
| The router | the one road out of the street; on Kev's list until Thursday |
| **The camera** | unnamed and unbranded, at 192.168.1.142, first seen 11 days ago. Telnet open, a settings page with no password, and a door punched through the router to the internet |

## The week at a glance

| day | what happens | the idea it teaches |
|---|---|---|
| (cold open) | the dinner-table guess: seven, but really eighteen | there are more devices than you think |
| Monday | moving in; the roll call | the network as a street with house numbers |
| Tuesday | the mystery camera | ports as doors; Telnet as a PIN on a postcard; the hole through the router |
| Wednesday | the router is on Kev's list | a flaw exists vs a flaw in use (KEV); the 30-day figure |
| Thursday | update day; this computer | firmware and updates are the fix; the antivirus does its own job |
| Friday | the phone book that says no | DNS, Blocking, gadgets phoning home, honest limits |
| Saturday | the router thought experiment; finding the camera | what depends on what (reliance, not traffic); Lens |
| Sunday | the report | the safety score, Fix these first, severity words |
| (close) | seventeen, and the printer | privacy, own network only, 'this is manageable' |

---

## Scene 1: How many things are on your Wi-Fi?  `01-cold-open`  (~38 s)

**Purpose.** Cold-open joke. It also sets up the whole story: there are far more gadgets at home than anyone thinks.

**Explains:** your home network and why it has far more devices than you think

**Narration**

> Here's a game for your next family dinner. [beat] Ask everyone: how many things in this house are on the Wi-Fi? [beat 1.2] This family guessed seven. Phones, laptops, the TV. [beat] Dad asked whether the printer counts. [beat] The printer counts. [beat] The printer would like it noted that it has always counted. [beat 1.2] So does the lamp. And the heater. The doorbell, the speakers, the games console. [beat] And one camera that nobody [beat] — and I cannot stress this enough — nobody remembers buying. [beat 1.2] The real answer is eighteen.

**On screen.** Illustrated slide, cream stone background from the Stone & Sage palette (bg #e5e0d5, ink #1f2d29). A dinner table seen from above with four plates and speech bubbles reading '7?', then '...the printer?'. As the narration lists them, small line-drawn gadget icons pop in around the table edge with a soft sage outline: printer, lamp, heater plug, doorbell, two speakers, console, kitchen Echo. The last one is a camera silhouette with a '?' in brick red (#842a2f). On 'eighteen' a counter in the corner ticks 7 up to 18.

**Caption:** *How many things are on your Wi-Fi?*

**Jokes in this scene**

- The printer would like it noted that it has always counted (set-up for the closing callback).
- The camera that nobody remembers buying.

---

## Scene 2: Meet the new housemate  `02-title-and-housemate`  (~40 s)

**Purpose.** Introduce Home SOC as the calm housemate: what it is, what it is not, and that it is free and runs at home.

**Explains:** none (the honest scope: not an antivirus, not a shield)

**Narration**

> Enter the new housemate: Home SOC. Big companies have a Security Operations Centre, where a team watches the network all day. This is the home version, minus the room, the team and the budget. It's a free program for a Windows PC you already own. It looks around, explains what it finds in plain words, and points you to the fix. [beat] It's not an antivirus, and not a force field. It's the housemate who says, 'Did you know the back door's open?' [beat] Not the one who tackles burglars. [beat] That's more of a Labrador thing.

**On screen.** Title card: 'Home SOC' in the serif title face (Palatino) with the subtitle 'Home network safety', sage leaf dot beside the brand as in the sidebar. Then an illustrated slide: a cosy kitchen table with a laptop on it (the housemate), a mug and a notepad. Two plain lists side by side on linen cards: 'Does: looks, explains, points to the fix' and 'Doesn't: replace your antivirus, stop every attack'. On the Labrador line, a small sketched dog lies asleep under the table.

**Caption:** *Meet the new housemate*

**Jokes in this scene**

- 'This is the home version, minus the room, the team and the budget.'
- The housemate who notices the open back door, not the one who tackles burglars. 'That's more of a Labrador thing.'

---

## Scene 3: Monday: moving in  `03-monday-setup`  (~32 s)

**Purpose.** Show how little effort getting started takes, give the only-your-own-network rule, and show the calm status sentence on Home.

**Explains:** privacy / only scan networks you own (setup)

**Narration**

> Monday. Double-click the launcher, and a minute later it's running: no account, no administrator password. [beat] One rule: only check networks you own or run. Your house, yes. The café's, no. [beat] Give it five minutes: less time than the printer takes to decide whether it feels like printing. [beat] Then Home says, calmly: 'Your network needs attention: two things should be fixed today, and six more this week.' [beat] No sirens. Just a housemate with a list.

**On screen.** Dashboard: Home page, day theme (layout per shots/overview-day.png, with the plain-language layer). Start on a short illustrated insert of a launcher icon being double-clicked, then cut to Home. Highlight the one-sentence status banner at the top (the .status-banner.is-attention card) as it is read. Point the cursor at the 'Things to fix' nav item on the word 'list'.

**Caption:** *Monday: moving in*

**Jokes in this scene**

- Five minutes is less time than the printer takes to decide whether it feels like printing.
- 'Your house, yes. The café's, no.'

---

## Scene 4: Monday: the roll call  `04-monday-roll-call`  (~29 s)

**Purpose.** Explain the home network as a street with house numbers, and why there are so many devices. Point to the one row nobody can explain.

**Explains:** your home network and why it has far more devices than you think

**Narration**

> Roll call. Think of your network as a little street. Every gadget gets a house number, and the router is the one road out to the internet. [beat] Devices lists everyone who lives here. The Switch is offline. [beat] It's a school night. [beat] Why eighteen? 'Smart' now mostly means 'has Wi-Fi', and each one is a small computer someone has to keep updated. [beat] Which leaves one row nobody can explain.

**On screen.** Opens on an illustrated slide: a little street of houses, each with a number on the door (.20, .30, .31, .32 ...), and a road at the end marked 'router, the way out to the internet'. Then Dashboard: Devices (layout per shots/devices-day.png, plain-language columns Device / Kind / Online / Things to fix / Known). Slow scroll down the list of 18. Highlight the Nintendo Switch row showing 'Not connected'. Pass over the Kitchen Echo row, whose Known column reads 'Yes, it's ours' (no narration, a quiet visual beat). End with the cursor resting on the top row: 'Unnamed camera (192.168.1.142)', marked 'Not sure', which sorts first.

**Caption:** *Monday: the roll call*

**Jokes in this scene**

- The Switch is offline: 'It's a school night.'
- 'Smart' mostly means 'has Wi-Fi'.

---

## Scene 5: Tuesday: the mystery guest  `05-tuesday-open-doors`  (~38 s)

**Purpose.** Introduce the villain and explain open ports and services with the doors-and-windows analogy. Make clear that Home SOC only looks and never breaks in.

**Explains:** open ports / services (doors and windows on a house)

**Narration**

> Tuesday. 'Unnamed camera.' No brand, first seen eleven days ago. [beat] Family theories: a gift, a bargain, or 'it came free with something'. [beat] Think of every gadget as a house with numbered doors. Behind each open door is a service, like a web page or a video stream. Doors are how gadgets work, but each is also a way in, so fewer is safer. [beat] Home SOC walks round the outside, reading the signs on open doors. It never picks a lock. [beat] This camera has four open. [beat] One is door twenty-three.

**On screen.** Dashboard: Devices, then the camera's device page (/devices/<camera>). Highlight the page summary line, then the 'Open doors on this device' table with 4 rows (23 Telnet, 80 web page, 554 video stream, plus one more). Between the two, a short illustrated slide: a house with numbered doors; the three labelled 'web page', 'video', 'remote control' are ajar and the rest are closed. A torch-carrying figure walks round the outside reading the door signs.

**Caption:** *Tuesday: the mystery guest*

**Jokes in this scene**

- The theories about the camera: 'a gift, a bargain, or "it came free with something"'.
- 'It never picks a lock.' Home SOC as a polite visitor reading door signs.

---

## Scene 6: Tuesday: why the camera is the villain  `06-tuesday-telnet`  (~48 s)

**Purpose.** Explain Telnet and unencrypted logins, and the camera's hole through the router, and why this makes the camera the villain. End with a simple fix.

**Explains:** Telnet and unencrypted logins (why the camera is the villain)

**Narration**

> Door twenty-three is Telnet: remote control by typing, from 1969. [beat] It sends your password unscrambled, in plain text, like a PIN on a postcard. [beat] Nothing modern needs it, so: 'Fix now'. [beat] And the camera's settings page has no password at all. [beat 1.2] Then it got bold. It asked the router to open a door from the internet straight to that page. [beat] Routers allow this with a feature called Universal Plug and Play, [beat] which is exactly as careful as it sounds. [beat] The fix: switch that feature off on the router, and unplug the camera. Its software was abandoned in two thousand and five. [beat] It's not evil. Just very old on the inside.

**On screen.** Dashboard: Things to fix (layout per shots/findings-expanded-day.png), filtered to Needs attention. Open the camera's Telnet row. Point at the brick 'Fix now' badge with its word, then the detail pane in its new order: What's wrong / Why it matters / How to fix it / buttons ('I've seen this', 'I've fixed it'). Insert a short illustrated slide: a postcard with 'PASSWORD: admin' written on the back, passing through several hands. Then back to Things to fix: highlight the camera's second finding, the router door opened from the internet (plain title along the lines of 'Your router lets the internet reach this camera's settings page'). Keep 'Technical details' collapsed.

**Caption:** *Tuesday: why the camera is the villain*

**Jokes in this scene**

- The PIN on a postcard.
- 'Universal Plug and Play, which is exactly as careful as it sounds.' This laughs at the jargon, not the viewer.
- 'It's not evil. Just very old on the inside.'

---

## Scene 7: Wednesday: a flaw vs. a flaw in use  `07-wednesday-kev`  (~56 s)

**Purpose.** Explain known flaws and the difference between 'a flaw exists' and 'attackers are using it now' (KEV). Frame the percentage correctly.

**Explains:** known vulnerabilities and KEV (a flaw exists vs attackers are using it now; the 30-day figure explained correctly)

**Narration**

> Wednesday, the router. Known software flaws go on a public list. But 'a flaw exists' and 'attackers are using it now' are different things. [beat] One is a recall notice for your lock. The other is a neighbour saying, 'There've been break-ins on our street, all through that exact lock.' [beat] The US keeps a list of the second kind, called KEV: Known Exploited Vulnerabilities. [beat] Just think of him as Kev. Kev only lists what's actually happening. [beat 1.2] This router is on Kev's list. Known flaws, under Advanced, says: 'Attackers using it? Yes.' [beat] The ninety-four percent beside it isn't the chance you get attacked. It's the chance this flaw gets used somewhere in the world in the next thirty days. [beat] A forecast for the country, not your garden. [beat] Still, bring an umbrella.

**On screen.** Illustrated slide first: two envelopes side by side, a polite 'Recall notice' and a handwritten neighbour's note 'break-ins on our street, same lock'. Then Dashboard: Advanced > Known flaws, filtered so one row remains, the Home router. Highlight the plain 'What' column, then 'Attackers using it?' = Yes (KEV badge), then the percentage column. Production note: the router's make and model must not appear. Keep the product/CPE detail closed, and crop or soft-blur any vendor string, including the 'TP-Link' vendor cell on Devices, which is visible in the current seed. The villain stays unbranded, and so does the router.

**Caption:** *Wednesday: a flaw vs. a flaw in use*

**Jokes in this scene**

- 'Just think of him as Kev.' This mocks the tech world's naming habit, and it makes the term stick.
- A forecast for the country, not your garden: 'Still, bring an umbrella.' (it sets up Thursday's 'The umbrella is an update')

---

## Scene 8: Thursday: updates are the fix  `08-thursday-updates`  (~54 s)

**Purpose.** Updates and firmware are the fix, and Home SOC re-checks them. 'This computer' shows the antivirus doing its own job, and the reminder-button joke.

**Explains:** updates / firmware as the fix

**Narration**

> Thursday. The umbrella is an update. On a router it's called firmware: the maker fixing the lock once they learn it can be picked. [beat] Dad presses 'update', and the house is offline for ninety seconds. [beat] Exactly long enough for someone upstairs to shout, 'Is the internet down?' [beat] Say you've fixed it, and Home SOC's next check makes sure. [beat 1.2] One device it sees from the inside: This computer, the PC it lives on. The antivirus is on, and it caught a fake invoice this month: a program in a PDF costume. [beat] Catching that is the antivirus's job. Home SOC notices if it's ever switched off. [beat] And a Windows update is waiting. We've all pressed 'remind me tomorrow'. [beat] Tomorrow has been going on for a while.

**On screen.** Illustrated slide: a padlock with a small spanner and the label 'update = the maker fixes the lock'. Then Dashboard: Things to fix, hovering the 'I've fixed it' button so its tooltip shows ('rechecked on the next scan'). Then Dashboard: This computer (layout per shots/host-day.png, plain words: '26 of 35 safety settings are OK'). Highlight the antivirus panel (On / On / 1 day old), then the threat row, 'invoice_2026_08.pdf.exe', with its outcome. Then the 'Windows updates' card with the pending cumulative update.

**Caption:** *Thursday: updates are the fix*

**Jokes in this scene**

- Ninety seconds offline: 'Exactly long enough for someone upstairs to shout, "Is the internet down?"'
- A program in a PDF costume.
- 'We've all pressed "remind me tomorrow". Tomorrow has been going on for a while.' (the narrator includes themselves)

---

## Scene 9: Friday: the phone book that says no  `09-friday-blocking`  (~57 s)

**Purpose.** Explain DNS as the phone book and Blocking as a phone book that refuses bad numbers. Cover devices phoning home, and give the honest limits.

**Explains:** DNS and the blocking feature (ads, trackers, known-bad sites; devices phoning home)

**Narration**

> Friday: the phone book. Before visiting a website, gadgets look up where it lives. That's DNS. [beat] After a one-time setup and one change on your router, Home SOC becomes the house's phone book: one that can refuse. [beat] Ads, trackers, scam and malware sites get 'sorry, no listing'. That's Blocking, and here it refuses close to a third of lookups. [beat 1.2] On Friday, a message sent Ellie's phone towards a fake sign-in page. Those are built to fool everyone. [beat] Blocking refused, and Mum got a ping. [beat] The camera phones home all day, and the TV wanted to report what the family watches. They added a rule: no. [beat] Nobody asked the TV for a review. [beat] The limits: if this PC sleeps, lookups stop. Some gadgets bring their own phone book. It's a filter, not a force field.

**On screen.** Illustrated slide: a chunky phone book. A gadget asks 'where is example-shop?' and gets a number; a second asks for 'fake-sign-in' and the page reads 'sorry, no listing'. Then Dashboard: Blocking (layout per shots/dns-day.png, with the capture re-seeded so the 24-hour numbers are live): 'Websites looked up today' and 'Blocked today' KPIs, then the per-hour chart. Then What happened: highlight the 'Blocked a known-malicious domain' item for Ellie's iPhone (named, not the IP), and the 'Blocked … requests to ipcam-vendor.example' item for the unnamed camera. Then the exceptions list on Blocking (today's Overrides card): highlight the TV's 'always block' rule with its note ('viewing-data collection; blocked on purpose').

**Caption:** *Friday: the phone book that says no*

**Jokes in this scene**

- 'Sorry, no listing.'
- 'Nobody asked the TV for a review.' This is about the gadget, not a brand.
- Ellie's phone: 'Those are built to fool everyone.' The joke is on the scam, never on Ellie.

---

## Scene 10: Saturday: if the router dies  `10-saturday-what-depends`  (~47 s)

**Purpose.** Explain the 'what depends on what' map: what goes dark if the router dies. State plainly that it shows reliance, not traffic.

**Explains:** what depends on what: if the router dies, what goes dark (reliance, not traffic)

**Narration**

> Saturday. What if the router dies? What depends on what, under Advanced, lays the house out, left to right. [beat] Click the router. Seventeen devices lose the internet, but can still reach each other at home. [beat] So the printer can still print. [beat] Whether it will is between you and the printer. [beat 1.2] The page says it up front: this is not a map of conversations. Home SOC can't see what your gadgets say to each other, only who relies on whom. [beat] The printer offers printing to the whole house. Nobody's been seen using it, so no lines are drawn. [beat] Home SOC won't guess, so you can believe the lines it does draw.

**On screen.** Dashboard: Advanced > What depends on what (layout per shots/map-day.png and shots/map-blast-day.png, columns renamed The internet / Your router / Shared services / Your devices). Start on the calm sage-edged note at the top ('This is not a traffic diagram...'). Click the Home router node so the view dims everything the router does not affect, and the side panel shows the one-sentence answer. Production note: the existing blast shot landed on 'DNS resolution', so re-capture with the click on the router node. Then highlight the Epson printer node and its Printing service, which has no lines drawn to it. Circle the note once more on 'won't guess'.

**Caption:** *Saturday: if the router dies*

**Jokes in this scene**

- 'Whether it will is between you and the printer.' (the printer with a grudge)
- The printer announcing 'I can print!' to a house that never takes it up on the offer.

---

## Scene 11: Saturday: point, and it tells you  `11-saturday-lens`  (~57 s)

**Purpose.** Explain Lens: point the phone at a mystery box to learn what it is. Give the Android Chrome requirement, the one-time certificate step and the stickers, and be clear it is a viewfinder with a card.

**Explains:** Lens: point your phone at a mystery box and it tells you what it is

**Narration**

> Saturday afternoon: find the camera. Easy, until you're facing a shelf of identical white boxes. Every gadget maker on earth agreed on one design: 'small white box'. [beat] Lens fixes that. Point your phone at a gadget, and it tells you which one it is. [beat] It needs Chrome on Android, and a one-time setup. The phone won't recognise Home SOC's certificate. Fair: they've never met. Check the code matches your PC's, then trust it. [beat] Gadgets without a barcode get a sticker: a random code that tells a stranger nothing. [beat] Point, hold still, [beat] and a card appears: 'Unbranded camera. Not trusted. One thing to fix now.' [beat] A viewfinder with a card, not floating 3D labels. It's a hallway, not a sci-fi film. [beat] Dad unplugs it. [beat] Back to the drawer it almost certainly came from.

**On screen.** Illustrated slide: the existing 'lens_why' shelf of identical white boxes (from video/slides.py). Then the phone rig (video/phone.py, 390x844): the certificate fingerprint check on the pairing page, then the sticker sheet. Then the scan shot, the existing 'shelf' scene render with a real QR sticker on the camera: the reticle flashes and the information card slides up over the live view. Hold on the card's header and its plain headline line. The narration paraphrases the card: its real header reads as an unbranded camera, online and not trusted, and its headline counts six problems, one of them 'Fix now'. End on a small illustration: a hand closing a drawer on the camera.

**Caption:** *Saturday: point, and it tells you*

**Jokes in this scene**

- 'Every gadget maker on earth agreed on one design: "small white box".'
- The phone doesn't recognise the certificate: 'Fair: they've never met.'
- 'This is a hallway, not a sci-fi film.'
- The camera goes back to the drawer: the pay-off to the 'came free with something' theory.

---

## Scene 12: Sunday: the report  `12-sunday-score`  (~48 s)

**Purpose.** Explain the safety score, the Fix these first list and the severity words, and show progress in the Report and What happened pages.

**Explains:** the safety score and "fix these first"

**Narration**

> Sunday: the report. The safety score runs from zero to a hundred; higher is safer. This house began on ten: 'Needs work'. [beat] Sounds grim, but any 'Fix now' problem caps the score low, however tidy the rest is. So two problems hold the whole house down. [beat] Fix these first puts them in order. Telnet on the camera: plus four. The router flaw: plus four. Clear both, and the score roughly doubles. [beat] Each badge says how soon: Fix now, Fix this week, Worth fixing, When you have time, Good to know. [beat] Report shows the line creeping up. What happened keeps the diary: every newcomer, block and fix. [beat] Unlike the family group chat, it's in order.

**On screen.** Dashboard: Home (layout per shots/overview-day.png). Highlight the gauge with 'Safety 10/100 · Needs work' and the band word under it (brick grade caption). Then the 'Fix these first' card: highlight the two top rows with their '+4 points' pills. Then the five severity badges, each with its action word, shown as a legend row. Then Report ('Your safety report', layout per shots/summary-day.png): 'Is it getting better?' trend line and the 'Fixed' KPI. Then What happened (layout per shots/feed-day.png, zero chips hidden), scrolling the week's timeline.

**Caption:** *Sunday: the report*

**Jokes in this scene**

- 'Unlike the family group chat, it's in order.'

---

## Scene 13: Seventeen, and counting  `13-close`  (~52 s)

**Purpose.** Recap, give the honest privacy statement and the own-network rule, and leave the viewer feeling 'I can do this'. Callback to the cold open.

**Explains:** privacy: it runs at home, nothing leaves your house, no account, free

**Narration**

> So that's Home SOC: a calm housemate on a PC you already own. It counts your gadgets, checks the doors, and tells you plainly what matters. You do the fixing, a bit at a time. That part is very doable. [beat] It's free and open source. No account, no cloud. It downloads public lists of known trouble, and sends nothing out unless you ask it to ping your phone. What it learns about your house stays there. [beat] Only point it at networks you own or run. [beat 1.2] So next family dinner, when someone asks how many things are on the Wi-Fi, [beat] you'll know. [beat] Seventeen. [beat] The camera's in the drawer. [beat 1.2] The printer would like it noted that it is still here.

**On screen.** Illustrated slide: the dinner table from the cold open, with the same gadget icons around it, now all in calm sage outlines. The camera icon is gone and a small closed drawer sits in the corner. The counter reads 17. A line of three linen cards: 'Free & open source', 'No account, no cloud', 'Only your own network'. As an optional last beat before the title, show a 'where this is heading' insert of the healthy Home screen (shots/healthy-overview-day-1920.png), captioned on screen as illustrative. End card: 'Home SOC · Home network safety' in the serif face on stone.

**Caption:** *Seventeen, and counting*

**Jokes in this scene**

- The callback: 'you'll know. Seventeen. The camera's in the drawer.'
- Closing button: 'The printer would like it noted that it is still here.'

---

## Honesty check (every claim against the brief)

- **Not an antivirus, not a shield.** Scene 2 ('not an antivirus, and not a force field'), scene 8 ('Catching that is the antivirus's job. Home SOC notices if it's ever switched off.') and scene 9 ('a filter, not a force field'). The script never says it stops hackers.
- **Cannot see traffic.** Scene 10 says 'this is not a map of conversations' and 'can't see what your gadgets say to each other', and it shows the page's own note. The Lens card line in scene 11 makes no traffic claim.
- **The 30-day figure.** Scene 7: 'isn't the chance you get attacked. It's the chance this flaw gets used somewhere in the world in the next thirty days.' *Production flag:* DESIGN.md §8.1 item 9 proposes the label '94% chance of attack', and §8.3 proposes a 'Chance of attack' column. Both read as 'chance you get attacked'. Please relabel before capture, e.g. 'Used somewhere in next 30 days: 94%'. Otherwise the screen contradicts the narration.
- **Lens.** Chrome on Android, a one-time certificate check (compare the code, then trust it), and 'a viewfinder with a card, not floating 3D labels'.
- **Own networks only.** Said in scene 3 and again in scene 13.
- **Nothing leaves the house.** Scene 13 is worded carefully: 'No account, no cloud. It downloads public lists of known trouble, and sends nothing out unless you ask it to ping your phone. What it learns about your house stays there.' Notifications (ntfy, Discord, webhook) and the optional reputation lookups do send data out when you switch them on, so a flat 'nothing ever leaves' would not be true. Mum's 'ping' in scene 9 is one of those opt-in notifications.
- **Free and open source.** Scenes 2 and 13.
- **No real brand called insecure.** The camera is unbranded. The router's make and model must not appear on screen (see scene 7's production note: the current seed shows a real vendor and model in Devices and in the finding's technical title). The printer's findings are never mentioned; only its personality and its map node appear. The TV is 'the TV', and its tracking is shown as a rule the family chose.
- **Score maths.** 'Any Fix now problem caps the score low' matches the caps (one critical caps the score at 34, two at 20). 'Clear both, and the score roughly doubles' matches the previous walkthrough. The healthy screen in scene 13 is a doctored copy of the demo data and must be captioned as illustrative.
- **DNS numbers.** 'Close to a third' comes from the seeded 24-hour data, the same source as the technical film's `{dns_block_pct}`. Re-seed right before capture so the Blocking page is not the 8-day-old empty state in the renders. Otherwise the stale-data banner appears.

## Production notes

- **Voice.** The technical film used `en-US-AndrewMultilingualNeural` at -4%. A warmer read suits this cut. Keep the rate at or near -4% so the timing estimate holds. Keep the `[beat]` marks as real silences (split the SSML at each mark).
- **Names, not addresses.** The narration never reads out an IP address; 'Unnamed camera (192.168.1.142)' is on screen only. This depends on DESIGN.md §8.1 item 4.
- **New visuals needed.** The dinner-table slide (open and close), the street of numbered houses, the house with numbered doors, the postcard, the two envelopes, the padlock-and-spanner, the phone book, and the drawer. All are flat line illustrations in the Stone & Sage palette, with no stock photos of real products. The shelf, phone rig and QR scan shots already exist in `video/slides.py`, `video/phone.py` and `video/scene_render.py`.
- **Re-captures needed.** The 'what depends on what' view with the click on the router node (the existing blast shot hit 'DNS resolution'). Every dashboard page after the plain-language labels ship.
- **Timeline honesty.** The on-screen data is one snapshot. The story's 'Dad updates the router' and 'Dad unplugs the camera' are narrated as the family's week; the screens do not claim the score changed live.
