# Wispbyte patch: dashboard review decisions

The dashboard UI and the matching API route have been committed to the dashboard repository. The live Wispbyte service and the main bot are separate, so these small bot/API changes must also be applied to the files running on Wispbyte before the buttons can work end to end.

Do not reset, replace, or migrate the SQLite database for this change.

## 1. Main bot: cogs/jobs.py

Add this method inside the existing `Jobs` class, alongside the other `job_...` handlers:

```py
    async def job_review_decision(self, p: dict) -> dict:
        moderation = self.bot.get_cog("Moderation")
        if moderation is None:
            raise RuntimeError("Moderation cog is not loaded")
        return await moderation.decide_from_dashboard(
            review_id=int(p["review_id"]),
            action=str(p["action"]),
            actor_id=int(p["actor_id"]),
        )
```

## 2. Main bot: cogs/moderation.py

Add this method inside the existing `Moderation` class, immediately before `send_ban_notice`:

```py
    async def decide_from_dashboard(self, *, review_id: int, action: str, actor_id: int) -> dict:
        """Apply a dashboard decision using the same moderation rules as the Discord buttons."""
        if actor_id not in config.OWNER_IDS:
            raise PermissionError("Only a configured bot owner can decide reviews.")
        if action not in {"accept", "decline"}:
            raise ValueError("Invalid review action.")

        review = await db.get_review(review_id)
        if review is None:
            return {"ok": False, "reason": "review_not_found"}
        if review["status"] != "pending":
            return {"ok": False, "reason": "already_handled", "status": review["status"]}

        is_report = review["kind"] == "report"

        if action == "accept":
            if not await db.decide_review(review_id, "accepted", actor_id):
                return {"ok": False, "reason": "already_handled"}
            if not is_report:
                await db.set_ad(
                    review["guild_id"], review["content"], review["user_id"], approved=True
                )
                outcome = "accepted_and_published"
            else:
                outcome = "report_dismissed_ad_left_live"
            log.info("Dashboard owner %s accepted review #%s: %s", actor_id, review_id, outcome)
            return {"ok": True, "review_id": review_id, "outcome": outcome}

        # Decline: preserve the existing bot behavior (ban known submitter, remove ad,
        # and take down copies already delivered to partner servers).
        if not await db.decide_review(review_id, "declined", actor_id):
            return {"ok": False, "reason": "already_handled"}

        has_user = bool(review["user_id"])
        if has_user:
            await db.ban_user(review["user_id"], f"Declined review #{review_id}", actor_id)
        await db.remove_ad(review["guild_id"])
        self.start_takedown(review["guild_id"])
        notified = await self.send_ban_notice(review["user_id"]) if has_user else False

        outcome = "declined_ad_removed_user_banned" if has_user else "declined_ad_removed_author_unknown"
        log.warning(
            "Dashboard owner %s declined review #%s; notice_sent=%s",
            actor_id, review_id, notified
        )
        return {
            "ok": True,
            "review_id": review_id,
            "outcome": outcome,
            "ban_notice_sent": notified,
        }
```

## 3. Live Wispbyte API: backend/main.py

In the actual Wispbyte backend file (not just the GitHub copy), add `import db` beside the existing project imports. Then add the following model and route after the existing `/api/reviews` route:

```py
class ReviewDecisionInput(BaseModel):
    action: str


@app.post("/api/reviews/{review_id}/decision")
async def decide_review_from_dashboard(review_id: int, payload: ReviewDecisionInput, request: Request):
    user = current_user(request)
    actor_id = str(user["id"])

    # Dashboard staff access is not enough: require the designated owner and bot OWNER_IDS.
    owner_ids = {str(value) for value in getattr(config, "OWNER_IDS", set())}
    if actor_id != ADMIN_OWNER_ID or actor_id not in owner_ids:
        raise HTTPException(status_code=403, detail="Only a configured bot owner can decide reviews.")
    if payload.action not in {"accept", "decline"}:
        raise HTTPException(status_code=422, detail="Action must be accept or decline.")

    if not await db.main_alive():
        raise HTTPException(status_code=503, detail="The main Discord bot is not connected to the job queue.")

    with closing(connect_db()) as con:
        row = con.execute("SELECT id,status FROM reviews WHERE id=?", (review_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Review not found.")
    if row["status"] != "pending":
        raise HTTPException(status_code=409, detail="This review has already been handled.")

    job_id = await db.create_job("review_decision", {
        "review_id": review_id,
        "action": payload.action,
        "actor_id": int(actor_id),
    })

    with closing(connect_db()) as con:
        con.execute(
            "INSERT INTO admin_audit_logs(actor_id,action,target_id) VALUES (?,?,?)",
            (actor_id, "review_" + payload.action + "_queued", str(review_id)),
        )
        con.commit()

    return {"ok": True, "queued": True, "job_id": job_id, "review_id": review_id}
```

The route intentionally checks the main bot heartbeat and both owner allowlists before queuing anything. The bot checks `OWNER_IDS` again when it executes the job. The existing database review transition remains the final protection against duplicate decisions.

## 4. Restart and verify

After saving those three Wispbyte file changes, restart the main bot and the Wispbyte API service. Then sign in to the dashboard and try a pending review. The dashboard buttons call `POST /api/reviews/{id}/decision`; the API queues a `review_decision` job; the main bot performs the action.

If the main bot is offline, the API refuses to queue the decision. No existing reviews, premium records, codes, or database files are deleted by this patch.
