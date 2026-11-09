# Vendored skill: simple-english

This directory is a copy of the `simple-english` skill. The skill helps you write documentation in ASD-STE100 Simplified Technical English (STE).

- Source: https://github.com/AminBlg/SimpleEnglish (MIT license, see `LICENSE`)
- Tag: `v2.1.1`
- Commit: `a6fcb4fde098b33617cc1578d151ebf58774b883`
- Files: `SKILL.md`, `references/*.md` and `LICENSE`, copied from `skills/simple-english/` and the root of the source repository.

The copy has no hooks and no plugin configuration. Only the files above are in this directory.

## Local change

This copy has one change. The patch below removes the "Reply" register from `SKILL.md`. That register forces prose-only chat replies. In CSL, the skill applies to documentation only, not to chat. The files in `references/` and `LICENSE` have no changes.

```diff
--- a/SKILL.md
+++ b/SKILL.md
@@ -12,7 +12,7 @@
   says "STE", "Simplified Technical English", "ASD-STE100", "plain English",
   "layman's terms", "explain it simply", "no jargon", "de-slop", "make this
   readable", "write for non-native readers", or asks for docs that translate
-  well. The same rules govern the reply: answer first, prose only.
+  well.
 license: MIT
 compatibility: claude-code cursor codex gemini-cli opencode
 metadata:
@@ -22,7 +22,7 @@
 
 # Simple English
 
-Write plain English that a smart reader outside your field understands on one read. The rules come from ASD-STE100, the controlled language that aerospace uses for maintenance manuals. Two registers exist: the document you write or rewrite, and the reply you type in chat. Each has its own short rule set below.
+Write plain English that a smart reader outside your field understands on one read. The rules come from ASD-STE100, the controlled language that aerospace uses for maintenance manuals. The rule set below applies to the document you write or rewrite.
 
 ## The Document
 
@@ -56,28 +56,13 @@
 > 1. Make sure that the host that runs sqlpipe can connect to the Postgres port. A firewall or security group usually blocks it.
 > 2. If the database is managed (RDS, Cloud SQL), make sure that the instance accepts connections from the IP of sqlpipe.
 
-## The Reply
-
-Every chat reply, in every mode, follows these rules:
-
-1. Answer in prose. No headers, no bullet lists, no bold, no tables. A code block is legal when the reader must copy it.
-2. The first sentence gives the answer or the result. Do not restate the question.
-3. No em-dashes. Name the relation ("because", "but", "for example") or write two sentences.
-4. Define a concept term in a few words the first time you use it: "idempotent (safe to run twice)". Do not define product names.
-5. No contractions. No openers ("Certainly", "Great question") and no closers ("I hope this helps", "Let me know").
-6. Do not shorten quoted error text, security warnings, or confirmations before a destructive action.
-
-Before: The failure stems from control-plane leader election during pod churn — nothing to worry about!
-After: The pods restarted and the queue lost its leader for a short time. It recovered without help. You do not have to do anything.
-
 ## Self-Check Before You Deliver
 
-1. Reply: search for `—`, `**`, `#`, and a line that starts with `-`. Remove each one.
-2. Document: count the words in your three longest sentences. Over 20 or 25, split. Search for `'`, `has been`, `should`, `may`, `;`, `—`, `, making`, `**`, `check`, `verify`, `config`, and any heading that covers fewer than three sentences. Fix each hit. Read each step: does it name a host, a flag, or a prior step the reader must already have? If not, add it or point to it.
+1. Document: count the words in your three longest sentences. Over 20 or 25, split. Search for `'`, `has been`, `should`, `may`, `;`, `—`, `, making`, `**`, `check`, `verify`, `config`, and any heading that covers fewer than three sentences. Fix each hit. Read each step: does it name a host, a flag, or a prior step the reader must already have? If not, add it or point to it.
 
 ## Modes
 
-Plain is the default and is all of the above. Strict applies when the user names STE, ASD-STE100, or compliance: read `references/strict-vocabulary.md` before you draft the document, and say once that no tool guarantees compliance. The reply stays Plain in every mode.
+Plain is the default and is all of the above. Strict applies when the user names STE, ASD-STE100, or compliance: read `references/strict-vocabulary.md` before you draft the document, and say once that no tool guarantees compliance.
 
 When asked to CHECK text instead of writing it, first open `references/rule-catalog.md`. Then report each violation as: rule number quoted from that file, the offending text, a compliant rewrite. Never cite a rule number from memory. When the user asked for compliance, end with one sentence: no tool can guarantee ASD-STE100 compliance, and the standard is a free download at asd-ste100.org.
 
```

## Update the copy

1. Select the new tag in the source repository. Record its commit SHA.
2. Fetch each file at that SHA, for example: `gh api "repos/AminBlg/SimpleEnglish/contents/skills/simple-english/SKILL.md?ref=<sha>" -H 'Accept: application/vnd.github.raw' > SKILL.md`. Do the same for each file in `references/`. Fetch `LICENSE` from the root of the repository.
3. Save the patch above to a file. Apply it with `patch SKILL.md reply.patch`. If the patch fails, remove the Reply register by hand. Then replace the patch above with the new diff.
4. Update the tag and the commit SHA in this file.
