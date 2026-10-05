## [Unreleased]

### Fixed — Devin Review (#678): `received_*` 節異字検出群 (138 検出器) がヘッダ区画ではなくメッセージ全体を走査しており、本文中の `Received:` 風行で誤発火していた問題を修正。全検出器を `header_end` (最初の空行) 区画へ統一。
### Security — D2043: `Message-ID:` 系欄 (refs 以外) の識別子前の隔離コメントを検出 — `Envelope` に `msgid_comment_lead` を追加 (refs 側 `refs_comment_lead`、直結 `)<`/`>(` の `msgid_paren` の補完)。
### Security — D2044: `Subject:` の地域返信・転送接頭語 (`AW:`/`SV:`/`RIF:`/`YNT:` 等) を検出 — `Envelope` に `subject_locale_prefix` を追加 (`encoded_re_subject` の補完)。
### Security — D2045: `Resent-*` ブロックの受取欄 (`Resent-To:`/`Cc:`/`Bcc:`) 全欠落を検出 — `Envelope` に `resent_no_recipient` を追加 (D1476 `incomplete_resent` の補完)。
### Security — D2699: `X-Confirm-Reading-To:` 欄のドメイン側低線宛名値 (`a@xample_.com` 形) を閲覧確認先ずれとして検出 — `Envelope` に `confirm_reading_underscore` を追加。
### Security — D2700: `Resent-Reply-To:` 欄のドメイン側低線宛名値を再送返信口ずれとして検出 — `Envelope` に `resent_reply_to_underscore` を追加。
### Security — D2701: `Apparently-Resent-*:` 系欄のドメイン側低線宛名値を再送残渣ずれとして検出 — `Envelope` に `apparently_resent_underscore` を追加。
### Security — D2702: `X-Original-Rcpt-To:` 系欄のドメイン側低線宛名値を元受取人ずれとして検出 — `Envelope` に `x_orig_rcpt_to_underscore` を追加。
### Security — D2703: `Envelope-To:`/`X-Envelope-To:` 系欄のローカル部プラス宛名値 (`a+b@y` 形) を封書宛先ずれとして検出 — `Envelope` に `env_to_plus_local` を追加。
### Security — D2704: `Delivered-To:` 欄のローカル部プラス宛名値を配達履歴ずれとして検出 — `Envelope` に `delivered_to_plus_local` を追加。
### Security — D2705: `X-Envelope-From:`/`X-MailFrom:` 等欄のローカル部プラス宛名値を封書差出人ずれとして検出 — `Envelope` に `env_from_plus_local` を追加。
### Security — D2706: `Errors-To:` 欄のローカル部プラス宛名値を返送先ずれとして検出 — `Envelope` に `errors_to_plus_local` を追加。
### Security — D2559: `Envelope-To:`/`X-Envelope-To:` 系欄のドメイン側縦線宛名値 (`a@xample|.com` 形) を封書宛先ずれとして検出 — `Envelope` に `env_to_pipe` を追加。
### Security — D2560: `Delivered-To:` 欄のドメイン側縦線宛名値を配達履歴ずれとして検出 — `Envelope` に `delivered_to_pipe` を追加。
### Security — D2561: `X-Envelope-From:`/`X-MailFrom:` 等欄のドメイン側縦線宛名値を封書差出人ずれとして検出 — `Envelope` に `env_from_pipe` を追加。
### Security — D2562: `Errors-To:` 欄のドメイン側縦線宛名値を返送先ずれとして検出 — `Envelope` に `errors_to_pipe` を追加。
### Security — D2519: `X-Original-Cc:` のイコール宛名値 (元副宛記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `x_orig_cc_eq` を追加。
### Security — D2520: `X-Original-Reply-To:` のイコール宛名値 (元返信口記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `x_orig_reply_to_eq` を追加。
### Security — D2521: `Disposition-Notification-To:` のイコール宛名値 (開封通知先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `disposition_to_eq` を追加。
### Security — D2522: `Return-Receipt-To:` のイコール宛名値 (受領通知先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `return_receipt_eq` を追加。
### Security — D2555: `X-Confirm-Reading-To:` 欄のドメイン側アンパサンド宛名値 (`a@xample&.com` 形) を閲覧確認先ずれとして検出 — `Envelope` に `confirm_reading_amp` を追加。
### Security — D2556: `Resent-Reply-To:` 欄のドメイン側アンパサンド宛名値を再送返信口ずれとして検出 — `Envelope` に `resent_reply_to_amp` を追加。
### Security — D2557: `Apparently-Resent-*:` 系欄のドメイン側アンパサンド宛名値を再送残渣ずれとして検出 — `Envelope` に `apparently_resent_amp` を追加。
### Security — D2558: `X-Original-Rcpt-To:` 系欄のドメイン側アンパサンド宛名値を元受取人ずれとして検出 — `Envelope` に `x_orig_rcpt_to_amp` を追加。
### Security — D2523: `X-Confirm-Reading-To:` のイコール宛名値 (閲覧確認先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `confirm_reading_eq` を追加。
### Security — D2524: `Resent-Reply-To:` のイコール宛名値 (再送返信口記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `resent_reply_to_eq` を追加。
### Security — D2525: `Apparently-Resent-*:` 系のイコール宛名値 (再送残渣記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `apparently_resent_eq` を追加。
### Security — D2526: `X-Original-Rcpt-To:` 系のイコール宛名値 (元受取人記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `x_orig_rcpt_to_eq` を追加。
### Security — D2547: `Apparently-To:`/`X-Apparently-To:` 系欄のドメイン側アンパサンド宛名値 (`a@xample&.com` 形) を見せ宛ずれとして検出 — `Envelope` に `apparently_to_amp` を追加。
### Security — D2548: `Apparently-From:`/`Apparently-Sender:` 系欄のドメイン側アンパサンド宛名値を表差出人ずれとして検出 — `Envelope` に `apparently_from_amp` を追加。
### Security — D2549: `X-Original-To:` 欄のドメイン側アンパサンド宛名値を元宛先ずれとして検出 — `Envelope` に `x_orig_to_amp` を追加。
### Security — D2550: `X-Original-From:` 欄のドメイン側アンパサンド宛名値を元差出人ずれとして検出 — `Envelope` に `x_orig_from_amp` を追加。
### Security — D2535: `X-Original-Cc:` の開き波括弧宛名値 (元副宛記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_cc_lbrace` を追加。
### Security — D2536: `X-Original-Reply-To:` の開き波括弧宛名値 (元返信口記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_reply_to_lbrace` を追加。
### Security — D2537: `Disposition-Notification-To:` の開き波括弧宛名値 (開封通知先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `disposition_to_lbrace` を追加。
### Security — D2538: `Return-Receipt-To:` の開き波括弧宛名値 (受領通知先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `return_receipt_lbrace` を追加。
### Security — D2531: `Apparently-To:`/`X-Apparently-To:` 系の開き波括弧宛名値 (見せ宛記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `apparently_to_lbrace` を追加。
### Security — D2532: `Apparently-From:`/`Apparently-Sender:` 系の開き波括弧宛名値 (表差出人記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `apparently_from_lbrace` を追加。
### Security — D2533: `X-Original-To:` の開き波括弧宛名値 (元宛先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_to_lbrace` を追加。
### Security — D2534: `X-Original-From:` の開き波括弧宛名値 (元差出人記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_from_lbrace` を追加。
### Security — D2531: `Apparently-To:`/`X-Apparently-To:` 系の開き波括弧宛名値 (見せ宛記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `apparently_to_lbrace` を追加。
### Security — D2532: `Apparently-From:`/`Apparently-Sender:` 系の開き波括弧宛名値 (表差出人記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `apparently_from_lbrace` を追加。
### Security — D2533: `X-Original-To:` の開き波括弧宛名値 (元宛先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_to_lbrace` を追加。
### Security — D2534: `X-Original-From:` の開き波括弧宛名値 (元差出人記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `x_orig_from_lbrace` を追加。
### Security — D2527: `Envelope-To:`/`X-Envelope-To:` 系の開き波括弧宛名値 (封書宛先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `env_to_lbrace` を追加。
### Security — D2528: `Delivered-To:` の開き波括弧宛名値 (配達履歴記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `delivered_to_lbrace` を追加。
### Security — D2529: `X-Envelope-From:`/`X-MailFrom:` 等の開き波括弧宛名値 (封書差出人記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `env_from_lbrace` を追加。
### Security — D2530: `Errors-To:` の開き波括弧宛名値 (返送先記録のドメイン側孤立開き波括弧異形) を検出 — `Envelope` に `errors_to_lbrace` を追加。
### Security — D2551: `X-Original-Cc:` 欄のドメイン側アンパサンド宛名値 (`a@xample&.com` 形) を元副宛ずれとして検出 — `Envelope` に `x_orig_cc_amp` を追加。
### Security — D2552: `X-Original-Reply-To:` 欄のドメイン側アンパサンド宛名値を元返信口ずれとして検出 — `Envelope` に `x_orig_reply_to_amp` を追加。
### Security — D2553: `Disposition-Notification-To:` 欄のドメイン側アンパサンド宛名値を開封通知先ずれとして検出 — `Envelope` に `disposition_to_amp` を追加。
### Security — D2554: `Return-Receipt-To:` 欄のドメイン側アンパサンド宛名値を受領通知先ずれとして検出 — `Envelope` に `return_receipt_amp` を追加。
### Security — D2543: `Envelope-To:`/`X-Envelope-To:` 系欄のドメイン側アンパサンド宛名値 (`a@xample&.com` 形) を封書宛先ずれとして検出 — `Envelope` に `env_to_amp` を追加。
### Security — D2544: `Delivered-To:` 欄のドメイン側アンパサンド宛名値を配達履歴ずれとして検出 — `Envelope` に `delivered_to_amp` を追加。
### Security — D2545: `X-Envelope-From:`/`X-MailFrom:` 等欄のドメイン側アンパサンド宛名値を封書差出人ずれとして検出 — `Envelope` に `env_from_amp` を追加。
### Security — D2546: `Errors-To:` 欄のドメイン側アンパサンド宛名値を返送先ずれとして検出 — `Envelope` に `errors_to_amp` を追加。
### Security — D2539: `X-Confirm-Reading-To:` 欄のドメイン側開き波括弧宛名値 (`a@xample{.com` 形) を閲覧確認先ずれとして検出 — `Envelope` に `confirm_reading_lbrace` を追加。
### Security — D2540: `Resent-Reply-To:` 欄のドメイン側開き波括弧宛名値を再送返信口ずれとして検出 — `Envelope` に `resent_reply_to_lbrace` を追加。
### Security — D2541: `Apparently-Resent-*:` 系欄のドメイン側開き波括弧宛名値を再送残渣ずれとして検出 — `Envelope` に `apparently_resent_lbrace` を追加。
### Security — D2542: `X-Original-Rcpt-To:` 系欄のドメイン側開き波括弧宛名値を元受取人ずれとして検出 — `Envelope` に `x_orig_rcpt_to_lbrace` を追加。
### Security — D2563: `Apparently-To:`/`X-Apparently-To:` 系欄のドメイン側縦線宛名値を見せ宛ずれとして検出 — `Envelope` に `apparently_to_pipe` を追加。
### Security — D2564: `Apparently-From:`/`Apparently-Sender:` 系欄のドメイン側縦線宛名値を表差出人ずれとして検出 — `Envelope` に `apparently_from_pipe` を追加。
### Security — D2565: `X-Original-To:` 欄のドメイン側縦線宛名値を元宛先ずれとして検出 — `Envelope` に `x_orig_to_pipe` を追加。
### Security — D2566: `X-Original-From:` 欄のドメイン側縦線宛名値を元差出人ずれとして検出 — `Envelope` に `x_orig_from_pipe` を追加。
### Security — D2571: `X-Confirm-Reading-To:` 欄のドメイン側縦線宛名値を閲覧確認先ずれとして検出 — `Envelope` に `confirm_reading_pipe` を追加。
### Security — D2572: `Resent-Reply-To:` 欄のドメイン側縦線宛名値を再送返信口ずれとして検出 — `Envelope` に `resent_reply_to_pipe` を追加。
### Security — D2573: `Apparently-Resent-*:` 系欄のドメイン側縦線宛名値を再送残渣ずれとして検出 — `Envelope` に `apparently_resent_pipe` を追加。
### Security — D2574: `X-Original-Rcpt-To:` 系欄のドメイン側縦線宛名値を元受取人ずれとして検出 — `Envelope` に `x_orig_rcpt_to_pipe` を追加。
### Security — D2575: `Envelope-To:`/`X-Envelope-To:` 系欄のドメイン側波線宛名値 (`a@xample~.com` 形) を封書宛先ずれとして検出 — `Envelope` に `env_to_tilde` を追加。
### Security — D2576: `Delivered-To:` 欄のドメイン側波線宛名値を配達履歴ずれとして検出 — `Envelope` に `delivered_to_tilde` を追加。
### Security — D2577: `X-Envelope-From:`/`X-MailFrom:` 等欄のドメイン側波線宛名値を封書差出人ずれとして検出 — `Envelope` に `env_from_tilde` を追加。
### Security — D2578: `Errors-To:` 欄のドメイン側波線宛名値を返送先ずれとして検出 — `Envelope` に `errors_to_tilde` を追加。
### Security — D2567: `X-Original-Cc:` 欄のドメイン側縦線宛名値を元副宛ずれとして検出 — `Envelope` に `x_orig_cc_pipe` を追加。
### Security — D2568: `X-Original-Reply-To:` 欄のドメイン側縦線宛名値を元返信口ずれとして検出 — `Envelope` に `x_orig_reply_to_pipe` を追加。
### Security — D2569: `Disposition-Notification-To:` 欄のドメイン側縦線宛名値を開封通知先ずれとして検出 — `Envelope` に `disposition_to_pipe` を追加。
### Security — D2570: `Return-Receipt-To:` 欄のドメイン側縦線宛名値を受領通知先ずれとして検出 — `Envelope` に `return_receipt_pipe` を追加。
### Security — D2579: `Apparently-To:`/`X-Apparently-To:` 系欄のドメイン側波線宛名値 (`a@xample~.com` 形) を見せ宛ずれとして検出 — `Envelope` に `apparently_to_tilde` を追加。
### Security — D2580: `Apparently-From:`/`Apparently-Sender:` 系欄のドメイン側波線宛名値を表差出人ずれとして検出 — `Envelope` に `apparently_from_tilde` を追加。
### Security — D2581: `X-Original-To:` 欄のドメイン側波線宛名値を元宛先ずれとして検出 — `Envelope` に `x_orig_to_tilde` を追加。
### Security — D2582: `X-Original-From:` 欄のドメイン側波線宛名値を元差出人ずれとして検出 — `Envelope` に `x_orig_from_tilde` を追加。
### Security — D2515: `Apparently-To:`/`X-Apparently-To:` 系のイコール宛名値 (見せ宛記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `apparently_to_eq` を追加。
### Security — D2516: `Apparently-From:`/`Apparently-Sender:` 系のイコール宛名値 (表差出人記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `apparently_from_eq` を追加。
### Security — D2517: `X-Original-To:` のイコール宛名値 (元宛先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `x_orig_to_eq` を追加。
### Security — D2518: `X-Original-From:` のイコール宛名値 (元差出人記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `x_orig_from_eq` を追加。
### Security — D2511: `Envelope-To:`/`X-Envelope-To:` 系のイコール宛名値 (封書宛先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `env_to_eq` を追加。
### Security — D2512: `Delivered-To:` のイコール宛名値 (配達履歴記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `delivered_to_eq` を追加。
### Security — D2513: `X-Envelope-From:`/`X-MailFrom:` 等のイコール宛名値 (封書差出人記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `env_from_eq` を追加。
### Security — D2514: `Errors-To:` のイコール宛名値 (返送先記録のドメイン側孤立イコール異形) を検出 — `Envelope` に `errors_to_eq` を追加。
### Security — D2507: `X-Confirm-Reading-To:` のプラス宛名値 (閲覧確認先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `confirm_reading_plus` を追加。
### Security — D2508: `Resent-Reply-To:` のプラス宛名値 (再送返信口記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `resent_reply_to_plus` を追加。
### Security — D2509: `Apparently-Resent-*:` 系のプラス宛名値 (再送残渣記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `apparently_resent_plus` を追加。
### Security — D2510: `X-Original-Rcpt-To:` 系のプラス宛名値 (元受取人記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `x_orig_rcpt_to_plus` を追加。
### Security — D2503: `X-Original-Cc:` のプラス宛名値 (元副宛記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `x_orig_cc_plus` を追加。
### Security — D2504: `X-Original-Reply-To:` のプラス宛名値 (元返信口記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `x_orig_reply_to_plus` を追加。
### Security — D2505: `Disposition-Notification-To:` のプラス宛名値 (開封通知先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `disposition_to_plus` を追加。
### Security — D2506: `Return-Receipt-To:` のプラス宛名値 (受領通知先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `return_receipt_plus` を追加。
### Security — D2499: `Apparently-To:`/`X-Apparently-To:` 系のプラス宛名値 (見せ宛記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `apparently_to_plus` を追加。
### Security — D2500: `Apparently-From:`/`Apparently-Sender:` 系のプラス宛名値 (表差出人記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `apparently_from_plus` を追加。
### Security — D2501: `X-Original-To:` のプラス宛名値 (元宛先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `x_orig_to_plus` を追加。
### Security — D2502: `X-Original-From:` のプラス宛名値 (元差出人記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `x_orig_from_plus` を追加。
### Security — D2495: `Envelope-To:`/`X-Envelope-To:` 系のプラス宛名値 (封書宛先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `env_to_plus` を追加。
### Security — D2496: `Delivered-To:` のプラス宛名値 (配達履歴記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `delivered_to_plus` を追加。
### Security — D2497: `X-Envelope-From:`/`X-MailFrom:` 等のプラス宛名値 (封書差出人記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `env_from_plus` を追加。
### Security — D2498: `Errors-To:` のプラス宛名値 (返送先記録のドメイン側孤立プラス異形) を検出 — `Envelope` に `errors_to_plus` を追加。
### Security — D2491: `X-Confirm-Reading-To:` の疑問符宛名値 (閲覧確認先記録の孤立疑問符異形) を検出 — `Envelope` に `confirm_reading_qmark` を追加。
### Security — D2492: `Resent-Reply-To:` の疑問符宛名値 (再送返信口記録の孤立疑問符異形) を検出 — `Envelope` に `resent_reply_to_qmark` を追加。
### Security — D2493: `Apparently-Resent-*:` 系の疑問符宛名値 (再送残渣記録の孤立疑問符異形) を検出 — `Envelope` に `apparently_resent_qmark` を追加。
### Security — D2494: `X-Original-Rcpt-To:` 系の疑問符宛名値 (元受取人記録の孤立疑問符異形) を検出 — `Envelope` に `x_orig_rcpt_to_qmark` を追加。
### Security — D2487: `X-Original-Cc:` の疑問符宛名値 (元副宛記録の孤立疑問符異形) を検出 — `Envelope` に `x_orig_cc_qmark` を追加。
### Security — D2488: `X-Original-Reply-To:` の疑問符宛名値 (元返信口記録の孤立疑問符異形) を検出 — `Envelope` に `x_orig_reply_to_qmark` を追加。
### Security — D2489: `Disposition-Notification-To:` の疑問符宛名値 (開封通知先記録の孤立疑問符異形) を検出 — `Envelope` に `disposition_to_qmark` を追加。
### Security — D2490: `Return-Receipt-To:` の疑問符宛名値 (受領通知先記録の孤立疑問符異形) を検出 — `Envelope` に `return_receipt_qmark` を追加。
### Security — D2483: `Apparently-To:`/`X-Apparently-To:` 系の疑問符宛名値 (見せ宛記録の孤立疑問符異形) を検出 — `Envelope` に `apparently_to_qmark` を追加。
### Security — D2484: `Apparently-From:`/`Apparently-Sender:` 系の疑問符宛名値 (表差出人記録の孤立疑問符異形) を検出 — `Envelope` に `apparently_from_qmark` を追加。
### Security — D2485: `X-Original-To:` の疑問符宛名値 (元宛先記録の孤立疑問符異形) を検出 — `Envelope` に `x_orig_to_qmark` を追加。
### Security — D2486: `X-Original-From:` の疑問符宛名値 (元差出人記録の孤立疑問符異形) を検出 — `Envelope` に `x_orig_from_qmark` を追加。
### Security — D2479: `Envelope-To:`/`X-Envelope-To:` 系の疑問符宛名値 (封書宛先記録の孤立疑問符異形) を検出 — `Envelope` に `env_to_qmark` を追加。
### Security — D2480: `Delivered-To:` の疑問符宛名値 (配達履歴記録の孤立疑問符異形) を検出 — `Envelope` に `delivered_to_qmark` を追加。
### Security — D2481: `X-Envelope-From:`/`X-MailFrom:` 等の疑問符宛名値 (封書差出人記録の孤立疑問符異形) を検出 — `Envelope` に `env_from_qmark` を追加。
### Security — D2482: `Errors-To:` の疑問符宛名値 (返送先記録の孤立疑問符異形) を検出 — `Envelope` に `errors_to_qmark` を追加。
### Security — D2475: `X-Confirm-Reading-To:` の逆引用符宛名値 (閲覧確認先記録の孤立引用符異形) を検出 — `Envelope` に `confirm_reading_apos` を追加。
### Security — D2476: `Resent-Reply-To:` の逆引用符宛名値 (再送返信口記録の孤立引用符異形) を検出 — `Envelope` に `resent_reply_to_apos` を追加。
### Security — D2477: `Apparently-Resent-*:` 系の逆引用符宛名値 (再送残渣記録の孤立引用符異形) を検出 — `Envelope` に `apparently_resent_apos` を追加。
### Security — D2478: `X-Original-Rcpt-To:` 系の逆引用符宛名値 (元受取人記録の孤立引用符異形) を検出 — `Envelope` に `x_orig_rcpt_to_apos` を追加。
### Security — D2471: `X-Original-Cc:` の逆引用符宛名値 (元副宛記録の孤立引用符異形) を検出 — `Envelope` に `x_orig_cc_apos` を追加。
### Security — D2472: `X-Original-Reply-To:` の逆引用符宛名値 (元返信口記録の孤立引用符異形) を検出 — `Envelope` に `x_orig_reply_to_apos` を追加。
### Security — D2473: `Disposition-Notification-To:` の逆引用符宛名値 (開封通知先記録の孤立引用符異形) を検出 — `Envelope` に `disposition_to_apos` を追加。
### Security — D2474: `Return-Receipt-To:` の逆引用符宛名値 (受領通知先記録の孤立引用符異形) を検出 — `Envelope` に `return_receipt_apos` を追加。
### Security — D2467: `Apparently-To:`/`X-Apparently-To:` 系の逆引用符宛名値 (見せ宛記録の孤立引用符異形) を検出 — `Envelope` に `apparently_to_apos` を追加。
### Security — D2468: `Apparently-From:`/`Apparently-Sender:` 系の逆引用符宛名値 (表差出人記録の孤立引用符異形) を検出 — `Envelope` に `apparently_from_apos` を追加。
### Security — D2469: `X-Original-To:` の逆引用符宛名値 (元宛先記録の孤立引用符異形) を検出 — `Envelope` に `x_orig_to_apos` を追加。
### Security — D2470: `X-Original-From:` の逆引用符宛名値 (元差出人記録の孤立引用符異形) を検出 — `Envelope` に `x_orig_from_apos` を追加。
### Security — D2463: `Envelope-To:`/`X-Envelope-To:` 系の逆引用符宛名値 (封書宛先記録の孤立引用符異形) を検出 — `Envelope` に `env_to_apos` を追加。
### Security — D2464: `Delivered-To:` の逆引用符宛名値 (配達履歴記録の孤立引用符異形) を検出 — `Envelope` に `delivered_to_apos` を追加。
### Security — D2465: `X-Envelope-From:`/`X-MailFrom:` 等の逆引用符宛名値 (封書差出人記録の孤立引用符異形) を検出 — `Envelope` に `env_from_apos` を追加。
### Security — D2466: `Errors-To:` の逆引用符宛名値 (返送先記録の孤立引用符異形) を検出 — `Envelope` に `errors_to_apos` を追加。
### Security — D2459: `X-Confirm-Reading-To:` の逆波括弧宛名値 (閲覧確認先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `confirm_reading_rbrace` を追加。
### Security — D2460: `Resent-Reply-To:` の逆波括弧宛名値 (再送返信口記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `resent_reply_to_rbrace` を追加。
### Security — D2461: `Apparently-Resent-*:` 系の逆波括弧宛名値 (再送残渣記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `apparently_resent_rbrace` を追加。
### Security — D2462: `X-Original-Rcpt-To:` 系の逆波括弧宛名値 (元受取人記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `x_orig_rcpt_to_rbrace` を追加。
### Security — D2455: `X-Original-Cc:` の逆波括弧宛名値 (元副宛記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `x_orig_cc_rbrace` を追加。
### Security — D2456: `X-Original-Reply-To:` の逆波括弧宛名値 (元返信口記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `x_orig_reply_to_rbrace` を追加。
### Security — D2457: `Disposition-Notification-To:` の逆波括弧宛名値 (開封通知先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `disposition_to_rbrace` を追加。
### Security — D2458: `Return-Receipt-To:` の逆波括弧宛名値 (受領通知先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `return_receipt_rbrace` を追加。
### Security — D2451: `Apparently-To:`/`X-Apparently-To:` 系の逆波括弧宛名値 (見せ宛記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `apparently_to_rbrace` を追加。
### Security — D2452: `Apparently-From:`/`Apparently-Sender:` 系の逆波括弧宛名値 (表差出人記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `apparently_from_rbrace` を追加。
### Security — D2453: `X-Original-To:` の逆波括弧宛名値 (元宛先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `x_orig_to_rbrace` を追加。
### Security — D2454: `X-Original-From:` の逆波括弧宛名値 (元差出人記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `x_orig_from_rbrace` を追加。
### Security — D2447: `Envelope-To:`/`X-Envelope-To:` 系の逆波括弧宛名値 (封書宛先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `env_to_rbrace` を追加。
### Security — D2448: `Delivered-To:` の逆波括弧宛名値 (配達履歴記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `delivered_to_rbrace` を追加。
### Security — D2449: `X-Envelope-From:`/`X-MailFrom:` 等の逆波括弧宛名値 (封書差出人記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `env_from_rbrace` を追加。
### Security — D2450: `Errors-To:` の逆波括弧宛名値 (返送先記録の孤立波括弧閉じ異形) を検出 — `Envelope` に `errors_to_rbrace` を追加。
### Security — D2443: `X-Confirm-Reading-To:` の逆角括弧宛名値 (閲覧確認先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `confirm_reading_rbracket` を追加。
### Security — D2444: `Resent-Reply-To:` の逆角括弧宛名値 (再送返信口記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `resent_reply_to_rbracket` を追加。
### Security — D2445: `Apparently-Resent-*:` 系の逆角括弧宛名値 (再送残渣記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `apparently_resent_rbracket` を追加。
### Security — D2446: `X-Original-Rcpt-To:` 系の逆角括弧宛名値 (元受取人記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `x_orig_rcpt_to_rbracket` を追加。
### Security — D2439: `X-Original-Cc:` の逆角括弧宛名値 (元副宛記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `x_orig_cc_rbracket` を追加。
### Security — D2440: `X-Original-Reply-To:` の逆角括弧宛名値 (元返信口記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `x_orig_reply_to_rbracket` を追加。
### Security — D2441: `Disposition-Notification-To:` の逆角括弧宛名値 (開封通知先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `disposition_to_rbracket` を追加。
### Security — D2442: `Return-Receipt-To:` の逆角括弧宛名値 (受領通知先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `return_receipt_rbracket` を追加。
### Security — D2435: `Apparently-To:`/`X-Apparently-To:` 系の逆角括弧宛名値 (見せ宛記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `apparently_to_rbracket` を追加。
### Security — D2436: `Apparently-From:`/`Apparently-Sender:` 系の逆角括弧宛名値 (表差出人記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `apparently_from_rbracket` を追加。
### Security — D2437: `X-Original-To:` の逆角括弧宛名値 (元宛先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `x_orig_to_rbracket` を追加。
### Security — D2438: `X-Original-From:` の逆角括弧宛名値 (元差出人記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `x_orig_from_rbracket` を追加。
### Security — D2431: `Envelope-To:`/`X-Envelope-To:` 系の逆角括弧宛名値 (封書宛先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `env_to_rbracket` を追加。
### Security — D2432: `Delivered-To:` の逆角括弧宛名値 (配達履歴記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `delivered_to_rbracket` を追加。
### Security — D2433: `X-Envelope-From:`/`X-MailFrom:` 等の逆角括弧宛名値 (封書差出人記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `env_from_rbracket` を追加。
### Security — D2434: `Errors-To:` の逆角括弧宛名値 (返送先記録の孤立角括弧閉じ異形) を検出 — `Envelope` に `errors_to_rbracket` を追加。
### Security — D2427: `X-Confirm-Reading-To:` の逆括弧宛名値 (閲覧確認先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `confirm_reading_rparen` を追加。
### Security — D2428: `Resent-Reply-To:` の逆括弧宛名値 (再送返信口記録の孤立括弧閉じ異形) を検出 — `Envelope` に `resent_reply_to_rparen` を追加。
### Security — D2429: `Apparently-Resent-*:` 系の逆括弧宛名値 (再送残渣記録の孤立括弧閉じ異形) を検出 — `Envelope` に `apparently_resent_rparen` を追加。
### Security — D2430: `X-Original-Rcpt-To:` 系の逆括弧宛名値 (元受取人記録の孤立括弧閉じ異形) を検出 — `Envelope` に `x_orig_rcpt_to_rparen` を追加。
### Security — D2423: `X-Original-Cc:` の逆括弧宛名値 (元副宛記録の孤立括弧閉じ異形) を検出 — `Envelope` に `x_orig_cc_rparen` を追加。
### Security — D2424: `X-Original-Reply-To:` の逆括弧宛名値 (元返信口記録の孤立括弧閉じ異形) を検出 — `Envelope` に `x_orig_reply_to_rparen` を追加。
### Security — D2425: `Disposition-Notification-To:` の逆括弧宛名値 (開封通知先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `disposition_to_rparen` を追加。
### Security — D2426: `Return-Receipt-To:` の逆括弧宛名値 (受領通知先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `return_receipt_rparen` を追加。
### Security — D2419: `Apparently-To:`/`X-Apparently-To:` 系の逆括弧宛名値 (見せ宛記録の孤立括弧閉じ異形) を検出 — `Envelope` に `apparently_to_rparen` を追加。
### Security — D2420: `Apparently-From:`/`Apparently-Sender:` 系の逆括弧宛名値 (表差出人記録の孤立括弧閉じ異形) を検出 — `Envelope` に `apparently_from_rparen` を追加。
### Security — D2421: `X-Original-To:` の逆括弧宛名値 (元宛先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `x_orig_to_rparen` を追加。
### Security — D2422: `X-Original-From:` の逆括弧宛名値 (元差出人記録の孤立括弧閉じ異形) を検出 — `Envelope` に `x_orig_from_rparen` を追加。
### Security — D2415: `Envelope-To:`/`X-Envelope-To:` 系の逆括弧宛名値 (封書宛先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `env_to_rparen` を追加。
### Security — D2416: `Delivered-To:` の逆括弧宛名値 (配達履歴記録の孤立括弧閉じ異形) を検出 — `Envelope` に `delivered_to_rparen` を追加。
### Security — D2417: `X-Envelope-From:`/`X-MailFrom:` 等の逆括弧宛名値 (封書差出人記録の孤立括弧閉じ異形) を検出 — `Envelope` に `env_from_rparen` を追加。
### Security — D2418: `Errors-To:` の逆括弧宛名値 (返送先記録の孤立括弧閉じ異形) を検出 — `Envelope` に `errors_to_rparen` を追加。
### Security — D2411: `X-Confirm-Reading-To:` のコロン宛名値 (閲覧確認先記録の接頭辞異形) を検出 — `Envelope` に `confirm_reading_colon` を追加。
### Security — D2412: `Resent-Reply-To:` のコロン宛名値 (再送返信口記録の接頭辞異形) を検出 — `Envelope` に `resent_reply_to_colon` を追加。
### Security — D2413: `Apparently-Resent-*:` 系のコロン宛名値 (再送残渣記録の接頭辞異形) を検出 — `Envelope` に `apparently_resent_colon` を追加。
### Security — D2414: `X-Original-Rcpt-To:` 系のコロン宛名値 (元受取人記録の接頭辞異形) を検出 — `Envelope` に `x_orig_rcpt_to_colon` を追加。
### Security — D2407: `X-Original-Cc:` のコロン宛名値 (元副宛記録の接頭辞異形) を検出 — `Envelope` に `x_orig_cc_colon` を追加。
### Security — D2408: `X-Original-Reply-To:` のコロン宛名値 (元返信口記録の接頭辞異形) を検出 — `Envelope` に `x_orig_reply_to_colon` を追加。
### Security — D2409: `Disposition-Notification-To:` のコロン宛名値 (開封通知先記録の接頭辞異形) を検出 — `Envelope` に `disposition_to_colon` を追加。
### Security — D2410: `Return-Receipt-To:` のコロン宛名値 (受領通知先記録の接頭辞異形) を検出 — `Envelope` に `return_receipt_colon` を追加。
### Security — D2403: `Apparently-To:`/`X-Apparently-To:` 系のコロン宛名値 (見せ宛記録の接頭辞異形) を検出 — `Envelope` に `apparently_to_colon` を追加。
### Security — D2404: `Apparently-From:`/`Apparently-Sender:` 系のコロン宛名値 (表差出人記録の接頭辞異形) を検出 — `Envelope` に `apparently_from_colon` を追加。
### Security — D2405: `X-Original-To:` のコロン宛名値 (元宛先記録の接頭辞異形) を検出 — `Envelope` に `x_orig_to_colon` を追加。
### Security — D2406: `X-Original-From:` のコロン宛名値 (元差出人記録の接頭辞異形) を検出 — `Envelope` に `x_orig_from_colon` を追加。
### Security — D2399: `Envelope-To:`/`X-Envelope-To:` 系のコロン宛名値 (封書宛先記録の接頭辞異形) を検出 — `Envelope` に `env_to_colon` を追加。
### Security — D2400: `Delivered-To:` のコロン宛名値 (配達履歴記録の接頭辞異形) を検出 — `Envelope` に `delivered_to_colon` を追加。
### Security — D2401: `X-Envelope-From:`/`X-MailFrom:` 等のコロン宛名値 (封書差出人記録の接頭辞異形) を検出 — `Envelope` に `env_from_colon` を追加。
### Security — D2402: `Errors-To:` のコロン宛名値 (返送先記録の接頭辞異形) を検出 — `Envelope` に `errors_to_colon` を追加。
### Security — D2395: `Envelope-To:`/`X-Envelope-To:` 系の逆斜線宛名値 (封書宛先記録の脱字異形) を検出 — `Envelope` に `env_to_bslash` を追加。
### Security — D2396: `Delivered-To:` の逆斜線宛名値 (配達履歴記録の脱字異形) を検出 — `Envelope` に `delivered_to_bslash` を追加。
### Security — D2397: `X-Envelope-From:`/`X-MailFrom:` 等の逆斜線宛名値 (封書差出人記録の脱字異形) を検出 — `Envelope` に `env_from_bslash` を追加。
### Security — D2398: `Errors-To:` の逆斜線宛名値 (返送先記録の脱字異形) を検出 — `Envelope` に `errors_to_bslash` を追加。
### Security — D2391: `X-Original-Cc:` 系の逆斜線宛名値 (元副宛記録の脱字異形) を検出 — `Envelope` に `x_orig_cc_bslash` を追加。
### Security — D2392: `X-Original-Reply-To:` の逆斜線宛名値 (元返信口記録の脱字異形) を検出 — `Envelope` に `x_orig_reply_to_bslash` を追加。
### Security — D2393: `Disposition-Notification-To:` の逆斜線宛名値 (開封通知先記録の脱字異形) を検出 — `Envelope` に `disposition_to_bslash` を追加。
### Security — D2394: `Return-Receipt-To:` の逆斜線宛名値 (受領通知先記録の脱字異形) を検出 — `Envelope` に `return_receipt_bslash` を追加。
### Security — D2387: `Apparently-To:`/`X-Apparently-To:` 系の逆斜線宛名値 (見せ宛記録の脱字異形) を検出 — `Envelope` に `apparently_to_bslash` を追加。
### Security — D2388: `Apparently-From:`/`Apparently-Sender:` 系の逆斜線宛名値 (表差出人記録の脱字異形) を検出 — `Envelope` に `apparently_from_bslash` を追加。
### Security — D2389: `X-Original-To:` の逆斜線宛名値 (元宛先記録の脱字異形) を検出 — `Envelope` に `x_orig_to_bslash` を追加。
### Security — D2390: `X-Original-From:` の逆斜線宛名値 (元差出人記録の脱字異形) を検出 — `Envelope` に `x_orig_from_bslash` を追加。
### Security — D2383: `X-Confirm-Reading-To:` の逆斜線宛名値 (閲覧確認先記録の脱字異形) を検出 — `Envelope` に `confirm_reading_bslash` を追加。
### Security — D2384: `Resent-Reply-To:` の逆斜線宛名値 (再送返信口記録の脱字異形) を検出 — `Envelope` に `resent_reply_to_bslash` を追加。
### Security — D2385: `Apparently-Resent-*:` 系の逆斜線宛名値 (再送残渣記録の脱字異形) を検出 — `Envelope` に `apparently_resent_bslash` を追加。
### Security — D2386: `X-Original-Rcpt-To:` 系の逆斜線宛名値 (元受取人記録の脱字異形) を検出 — `Envelope` に `x_orig_rcpt_to_bslash` を追加。
### Security — D2379: `X-Confirm-Reading-To:` の端ハイフンラベル宛名値 (閲覧確認先記録の DNS ラベル違反) を検出 — `Envelope` に `confirm_reading_hyph` を追加。
### Security — D2380: `Resent-Reply-To:` の端ハイフンラベル宛名値 (再送返信口記録の DNS ラベル違反) を検出 — `Envelope` に `resent_reply_to_hyph` を追加。
### Security — D2381: `Apparently-Resent-*:` 系の端ハイフンラベル宛名値 (再送残渣記録の DNS ラベル違反) を検出 — `Envelope` に `apparently_resent_hyph` を追加。
### Security — D2382: `X-Original-Rcpt-To:` 系の端ハイフンラベル宛名値 (元受取人記録の DNS ラベル違反) を検出 — `Envelope` に `x_orig_rcpt_to_hyph` を追加。
### Security — D2375: `X-Original-Cc:` の端ハイフンラベル宛名値 (元副宛記録の DNS ラベル違反) を検出 — `Envelope` に `x_orig_cc_hyph` を追加。
### Security — D2376: `X-Original-Reply-To:` の端ハイフンラベル宛名値 (元返信口記録の DNS ラベル違反) を検出 — `Envelope` に `x_orig_reply_to_hyph` を追加。
### Security — D2377: `Disposition-Notification-To:` の端ハイフンラベル宛名値 (開封通知先記録の DNS ラベル違反) を検出 — `Envelope` に `disposition_to_hyph` を追加。
### Security — D2378: `Return-Receipt-To:` の端ハイフンラベル宛名値 (受領通知先記録の DNS ラベル違反) を検出 — `Envelope` に `return_receipt_hyph` を追加。
### Security — D2371: `Apparently-To:`/`X-Apparently-To:` の端ハイフンラベル宛名値 (見せ宛記録の DNS ラベル違反) を検出 — `Envelope` に `apparently_to_hyph` を追加。
### Security — D2372: `Apparently-From:`/`Apparently-Sender:` 系の端ハイフンラベル宛名値 (表差出人記録の DNS ラベル違反) を検出 — `Envelope` に `apparently_from_hyph` を追加。
### Security — D2373: `X-Original-To:` の端ハイフンラベル宛名値 (元宛先記録の DNS ラベル違反) を検出 — `Envelope` に `x_orig_to_hyph` を追加。
### Security — D2374: `X-Original-From:` の端ハイフンラベル宛名値 (元差出人記録の DNS ラベル違反) を検出 — `Envelope` に `x_orig_from_hyph` を追加。
### Security — D2367: `Envelope-To:`/`X-Envelope-To:` の端ハイフンラベル宛名値 (封書宛先記録の DNS ラベル違反) を検出 — `Envelope` に `env_to_hyph` を追加。
### Security — D2368: `Delivered-To:` の端ハイフンラベル宛名値 (配達記録の DNS ラベル違反) を検出 — `Envelope` に `delivered_to_hyph` を追加。
### Security — D2369: `X-Envelope-From:`/`X-MailFrom:` 等の端ハイフンラベル宛名値 (封書差出人記録の DNS ラベル違反) を検出 — `Envelope` に `env_from_hyph` を追加。
### Security — D2370: `Errors-To:` の端ハイフンラベル宛名値 (返送先記録の DNS ラベル違反) を検出 — `Envelope` に `errors_to_hyph` を追加。
### Security — D2363: `X-Confirm-Reading-To:` の非 ASCII 宛名値 (閲覧確認先記録の EAI/国際化異形) を検出 — `Envelope` に `confirm_reading_eai` を追加。
### Security — D2364: `Resent-Reply-To:` の非 ASCII 宛名値 (再送返信口記録の EAI/国際化異形) を検出 — `Envelope` に `resent_reply_to_eai` を追加。
### Security — D2365: `Apparently-Resent-*:` 系の非 ASCII 宛名値 (再送残渣記録の EAI/国際化異形) を検出 — `Envelope` に `apparently_resent_eai` を追加。
### Security — D2366: `X-Original-Rcpt-To:` 系の非 ASCII 宛名値 (元受取人記録の EAI/国際化異形) を検出 — `Envelope` に `x_orig_rcpt_to_eai` を追加。
### Security — D2359: `X-Original-Cc:` の非 ASCII 宛名値 (元副宛記録の EAI/国際化異形) を検出 — `Envelope` に `x_orig_cc_eai` を追加。
### Security — D2360: `X-Original-Reply-To:` の非 ASCII 宛名値 (元返信口記録の EAI/国際化異形) を検出 — `Envelope` に `x_orig_reply_to_eai` を追加。
### Security — D2361: `Disposition-Notification-To:` の非 ASCII 宛名値 (開封通知先記録の EAI/国際化異形) を検出 — `Envelope` に `disposition_to_eai` を追加。
### Security — D2362: `Return-Receipt-To:` の非 ASCII 宛名値 (受領通知先記録の EAI/国際化異形) を検出 — `Envelope` に `return_receipt_eai` を追加。
### Security — D2355: `Apparently-To:`/`X-Apparently-To:` 系の非 ASCII 宛名値 (見せ宛記録の EAI/国際化異形) を検出 — `Envelope` に `apparently_to_eai` を追加。
### Security — D2356: `Apparently-From:`/`Apparently-Sender:` 系の非 ASCII 宛名値 (表差出人記録の EAI/国際化異形) を検出 — `Envelope` に `apparently_from_eai` を追加。
### Security — D2357: `X-Original-To:` の非 ASCII 宛名値 (元宛先記録の EAI/国際化異形) を検出 — `Envelope` に `x_orig_to_eai` を追加。
### Security — D2358: `X-Original-From:` の非 ASCII 宛名値 (元差出人記録の EAI/国際化異形) を検出 — `Envelope` に `x_orig_from_eai` を追加。
### Security — D2351: `Envelope-To:`/`X-Envelope-To:` の非 ASCII 宛名値 (封書宛先記録の EAI/国際化異形) を検出 — `Envelope` に `env_to_eai` を追加。
### Security — D2352: `Delivered-To:` の非 ASCII 宛名値 (配達記録の EAI/国際化異形) を検出 — `Envelope` に `delivered_to_eai` を追加。
### Security — D2353: `X-Envelope-From:`/`X-MailFrom:` 等の非 ASCII 宛名値 (封書差出人記録の EAI/国際化異形) を検出 — `Envelope` に `env_from_eai` を追加。
### Security — D2354: `Errors-To:` の非 ASCII 宛名値 (返送先記録の EAI/国際化異形) を検出 — `Envelope` に `errors_to_eai` を追加。
### Security — D2347: `X-Confirm-Reading-To:` のドメインリテラル宛名値 (閲覧確認先記録のリテラル異形) を検出 — `Envelope` に `confirm_reading_domlit` を追加。
### Security — D2348: `Resent-Reply-To:` のドメインリテラル宛名値 (再送返信口記録のリテラル異形) を検出 — `Envelope` に `resent_reply_to_domlit` を追加。
### Security — D2349: `Apparently-Resent-*:` 系のドメインリテラル宛名値 (再送残渣記録のリテラル異形) を検出 — `Envelope` に `apparently_resent_domlit` を追加。
### Security — D2350: `X-Original-Rcpt-To:` 系のドメインリテラル宛名値 (元受取人記録のリテラル異形) を検出 — `Envelope` に `x_orig_rcpt_to_domlit` を追加。
### Security — D2343: `X-Original-Cc:` のドメインリテラル宛名値 (元副宛記録のリテラル異形) を検出 — `Envelope` に `x_orig_cc_domlit` を追加。
### Security — D2344: `X-Original-Reply-To:` のドメインリテラル宛名値 (元返信口記録のリテラル異形) を検出 — `Envelope` に `x_orig_reply_to_domlit` を追加。
### Security — D2345: `Disposition-Notification-To:` のドメインリテラル宛名値 (開封通知先記録のリテラル異形) を検出 — `Envelope` に `disposition_to_domlit` を追加。
### Security — D2346: `Return-Receipt-To:` のドメインリテラル宛名値 (受領通知先記録のリテラル異形) を検出 — `Envelope` に `return_receipt_domlit` を追加。
### Security — D2339: `Apparently-To:` 系のドメインリテラル宛名値 (見せ宛記録のリテラル異形) を検出 — `Envelope` に `apparently_to_domlit` を追加。
### Security — D2340: `Apparently-From:` 系のドメインリテラル宛名値 (表差出人記録のリテラル異形) を検出 — `Envelope` に `apparently_from_domlit` を追加。
### Security — D2341: `X-Original-To:` のドメインリテラル宛名値 (元宛先記録のリテラル異形) を検出 — `Envelope` に `x_orig_to_domlit` を追加。
### Security — D2342: `X-Original-From:` のドメインリテラル宛名値 (元差出人記録のリテラル異形) を検出 — `Envelope` に `x_orig_from_domlit` を追加。
### Security — D2335: `Envelope-To:` 系のドメインリテラル宛名値 (`a@[1.2.3.4]` — 封書宛先記録のリテラル異形) を検出 — `Envelope` に `env_to_domlit` を追加。
### Security — D2336: `Delivered-To:` のドメインリテラル宛名値 (配達記録のリテラル異形) を検出 — `Envelope` に `delivered_to_domlit` を追加。
### Security — D2337: `X-Envelope-From:` 系のドメインリテラル宛名値 (封書差出人記録のリテラル異形) を検出 — `Envelope` に `env_from_domlit` を追加。
### Security — D2338: `Errors-To:` のドメインリテラル宛名値 (返送先記録のリテラル異形) を検出 — `Envelope` に `errors_to_domlit` を追加。
### Security — D2331: `X-Confirm-Reading-To:` のバン経路宛名値 (閲覧確認先記録の経路異形) を検出 — `Envelope` に `confirm_reading_bang` を追加。
### Security — D2332: `Resent-Reply-To:` のバン経路宛名値 (再送返信口記録の経路異形) を検出 — `Envelope` に `resent_reply_to_bang` を追加。
### Security — D2333: `Apparently-Resent-*:` 系のバン経路宛名値 (再送残渣記録の経路異形) を検出 — `Envelope` に `apparently_resent_bang` を追加。
### Security — D2334: `X-Original-Rcpt-To:` 系のバン経路宛名値 (元受取人記録の経路異形) を検出 — `Envelope` に `x_orig_rcpt_to_bang` を追加。
### Security — D2327: `X-Original-Cc:` のバン経路宛名値 (元副宛記録の経路異形) を検出 — `Envelope` に `x_orig_cc_bang` を追加。
### Security — D2328: `X-Original-Reply-To:` のバン経路宛名値 (元返信口記録の経路異形) を検出 — `Envelope` に `x_orig_reply_to_bang` を追加。
### Security — D2329: `Disposition-Notification-To:` のバン経路宛名値 (開封通知先記録の経路異形) を検出 — `Envelope` に `disposition_to_bang` を追加。
### Security — D2330: `Return-Receipt-To:` のバン経路宛名値 (受領通知先記録の経路異形) を検出 — `Envelope` に `return_receipt_bang` を追加。
### Security — D2323: `Apparently-To:` 系のバン経路宛名値 (見せ宛記録の経路異形) を検出 — `Envelope` に `apparently_to_bang` を追加。
### Security — D2324: `Apparently-From:` 系のバン経路宛名値 (表差出人記録の経路異形) を検出 — `Envelope` に `apparently_from_bang` を追加。
### Security — D2325: `X-Original-To:` のバン経路宛名値 (元宛先記録の経路異形) を検出 — `Envelope` に `x_orig_to_bang` を追加。
### Security — D2326: `X-Original-From:` のバン経路宛名値 (元差出人記録の経路異形) を検出 — `Envelope` に `x_orig_from_bang` を追加。
### Security — D2319: `Envelope-To:` 系のバン経路宛名値 (`a!b@x` — 封書宛先記録の経路異形) を検出 — `Envelope` に `env_to_bang` を追加。
### Security — D2320: `Delivered-To:` のバン経路宛名値 (配達記録の経路異形) を検出 — `Envelope` に `delivered_to_bang` を追加。
### Security — D2321: `X-Envelope-From:` 系のバン経路宛名値 (封書差出人記録の経路異形) を検出 — `Envelope` に `env_from_bang` を追加。
### Security — D2322: `Errors-To:` のバン経路宛名値 (返送先記録の経路異形) を検出 — `Envelope` に `errors_to_bang` を追加。
### Security — D2315: `X-Confirm-Reading-To:` のパーセント経路宛名値 (閲覧確認先記録の経路異形) を検出 — `Envelope` に `confirm_reading_pct` を追加。
### Security — D2316: `Resent-Reply-To:` のパーセント経路宛名値 (再送返信口記録の経路異形) を検出 — `Envelope` に `resent_reply_to_pct` を追加。
### Security — D2317: `Apparently-Resent-*:` 系のパーセント経路宛名値 (再送残渣記録の経路異形) を検出 — `Envelope` に `apparently_resent_pct` を追加。
### Security — D2318: `X-Original-Rcpt-To:` 系のパーセント経路宛名値 (元受取人記録の経路異形) を検出 — `Envelope` に `x_orig_rcpt_to_pct` を追加。
### Security — D2311: `X-Original-Cc:` のパーセント経路宛名値 (元副宛記録の経路異形) を検出 — `Envelope` に `x_orig_cc_pct` を追加。
### Security — D2312: `X-Original-Reply-To:` のパーセント経路宛名値 (元返信口記録の経路異形) を検出 — `Envelope` に `x_orig_reply_to_pct` を追加。
### Security — D2313: `Disposition-Notification-To:` のパーセント経路宛名値 (開封通知先記録の経路異形) を検出 — `Envelope` に `disposition_to_pct` を追加。
### Security — D2314: `Return-Receipt-To:` のパーセント経路宛名値 (受領通知先記録の経路異形) を検出 — `Envelope` に `return_receipt_pct` を追加。
### Security — D2307: `Apparently-To:` 系のパーセント経路宛名値 (`a%b@x` — 見せ宛記録の経路異形) を検出 — `Envelope` に `apparently_to_pct` を追加。
### Security — D2308: `Apparently-From:` 系のパーセント経路宛名値 (表差出人記録の経路異形) を検出 — `Envelope` に `apparently_from_pct` を追加。
### Security — D2309: `X-Original-To:` のパーセント経路宛名値 (元宛先記録の経路異形) を検出 — `Envelope` に `x_orig_to_pct` を追加。
### Security — D2310: `X-Original-From:` のパーセント経路宛名値 (元差出人記録の経路異形) を検出 — `Envelope` に `x_orig_from_pct` を追加。
### Security — D2303: `Envelope-To:` 系のパーセント経路宛名値 (`a%b@x` — 封書宛先記録の経路異形) を検出 — `Envelope` に `env_to_pct` を追加。
### Security — D2304: `Delivered-To:` のパーセント経路宛名値 (配達記録の経路異形) を検出 — `Envelope` に `delivered_to_pct` を追加。
### Security — D2305: `X-Envelope-From:` 系のパーセント経路宛名値 (封書差出人記録の経路異形) を検出 — `Envelope` に `env_from_pct` を追加。
### Security — D2306: `Errors-To:` のパーセント経路宛名値 (返送先記録の経路異形) を検出 — `Envelope` に `errors_to_pct` を追加。
### Security — D2299: `X-Confirm-Reading-To:` のセミコロン入り宛名値 (閲覧確認先記録の区切り異形) を検出 — `Envelope` に `confirm_reading_semiv` を追加。
### Security — D2300: `Resent-Reply-To:` のセミコロン入り宛名値 (再送返信口記録の区切り異形) を検出 — `Envelope` に `resent_reply_to_semiv` を追加。
### Security — D2301: `Apparently-Resent-*:` 系のセミコロン入り宛名値 (再送残渣記録の区切り異形) を検出 — `Envelope` に `apparently_resent_semiv` を追加。
### Security — D2302: `X-Original-Rcpt-To:` 系のセミコロン入り宛名値 (元受取人記録の区切り異形) を検出 — `Envelope` に `x_orig_rcpt_to_semiv` を追加。
### Security — D2295: `X-Original-Cc:` のセミコロン入り宛名値 (元副宛記録の区切り異形) を検出 — `Envelope` に `x_orig_cc_semiv` を追加。
### Security — D2296: `X-Original-Reply-To:` のセミコロン入り宛名値 (元返信口記録の区切り異形) を検出 — `Envelope` に `x_orig_reply_to_semiv` を追加。
### Security — D2297: `Disposition-Notification-To:` のセミコロン入り宛名値 (開封通知先記録の区切り異形) を検出 — `Envelope` に `disposition_to_semiv` を追加。
### Security — D2298: `Return-Receipt-To:` のセミコロン入り宛名値 (受領通知先記録の区切り異形) を検出 — `Envelope` に `return_receipt_semiv` を追加。
### Security — D2291: `Apparently-To:` 系のセミコロン入り宛名値 (`a@x;` — 見せ宛記録の区切り異形) を検出 — `Envelope` に `apparently_to_semiv` を追加。
### Security — D2292: `Apparently-From:` 系のセミコロン入り宛名値 (表差出人記録の区切り異形) を検出 — `Envelope` に `apparently_from_semiv` を追加。
### Security — D2293: `X-Original-To:` のセミコロン入り宛名値 (元宛先記録の区切り異形) を検出 — `Envelope` に `x_orig_to_semiv` を追加。
### Security — D2294: `X-Original-From:` のセミコロン入り宛名値 (元差出人記録の区切り異形) を検出 — `Envelope` に `x_orig_from_semiv` を追加。
### Security — D2287: `Envelope-To:` 系のセミコロン入り宛名値 (`a@x;`/`a@x;b@y` — 封書宛先記録の区切り異形) を検出 — `Envelope` に `env_to_semiv` を追加。
### Security — D2288: `Delivered-To:` のセミコロン入り宛名値 (配達記録の区切り異形) を検出 — `Envelope` に `delivered_to_semiv` を追加。
### Security — D2289: `X-Envelope-From:` 系のセミコロン入り宛名値 (封書差出人記録の区切り異形) を検出 — `Envelope` に `env_from_semiv` を追加。
### Security — D2290: `Errors-To:` のセミコロン入り宛名値 (返送先記録の区切り異形) を検出 — `Envelope` に `errors_to_semiv` を追加。
### Security — D2283: `X-Confirm-Reading-To:` の片側欠落宛名 (`@x`/`a@` — 閲覧確認先記録の addr-spec 違反) を検出 — `Envelope` に `confirm_reading_atside` を追加。
### Security — D2284: `Resent-Reply-To:` の片側欠落宛名 (再送返信口記録の addr-spec 違反) を検出 — `Envelope` に `resent_reply_to_atside` を追加。
### Security — D2285: `Apparently-Resent-*:` 系の片側欠落宛名 (再送残渣記録の addr-spec 違反) を検出 — `Envelope` に `apparently_resent_atside` を追加。
### Security — D2286: `X-Original-Rcpt-To:` 系の片側欠落宛名 (元受取人記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_rcpt_to_atside` を追加。
### Security — D2279: `X-Original-Cc:` の片側欠落宛名 (`@x`/`a@` — 元副宛記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_cc_atside` を追加。
### Security — D2280: `X-Original-Reply-To:` の片側欠落宛名 (元返信口記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_reply_to_atside` を追加。
### Security — D2281: `Disposition-Notification-To:` の片側欠落宛名 (開封通知先記録の addr-spec 違反) を検出 — `Envelope` に `disposition_to_atside` を追加。
### Security — D2282: `Return-Receipt-To:` の片側欠落宛名 (受領通知先記録の addr-spec 違反) を検出 — `Envelope` に `return_receipt_atside` を追加。
### Security — D2275: `Apparently-To:` 系の片側欠落宛名 (`@x`/`a@` — 見せ宛記録の addr-spec 違反) を検出 — `Envelope` に `apparently_to_atside` を追加。
### Security — D2276: `Apparently-From:` 系の片側欠落宛名 (表差出人記録の addr-spec 違反) を検出 — `Envelope` に `apparently_from_atside` を追加。
### Security — D2277: `X-Original-To:` の片側欠落宛名 (元宛先記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_to_atside` を追加。
### Security — D2278: `X-Original-From:` の片側欠落宛名 (元差出人記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_from_atside` を追加。
### Security — D2271: `Envelope-To:` 系の片側欠落宛名 (`@x`/`a@` — 封書宛先記録の addr-spec 違反) を検出 — `Envelope` に `env_to_atside` を追加。
### Security — D2272: `Delivered-To:` の片側欠落宛名 (配達記録の addr-spec 違反) を検出 — `Envelope` に `delivered_to_atside` を追加。
### Security — D2273: `X-Envelope-From:` 系の片側欠落宛名 (封書差出人記録の addr-spec 違反) を検出 — `Envelope` に `env_from_atside` を追加。
### Security — D2274: `Errors-To:` の片側欠落宛名 (返送先記録の addr-spec 違反) を検出 — `Envelope` に `errors_to_atside` を追加。
### Security — D2267: `X-Confirm-Reading-To:` の複数 `@` 値 (閲覧確認先記録の addr-spec 違反) を検出 — `Envelope` に `confirm_reading_atdup` を追加。
### Security — D2268: `Resent-Reply-To:` の複数 `@` 値 (再送返信口記録の addr-spec 違反) を検出 — `Envelope` に `resent_reply_to_atdup` を追加。
### Security — D2269: `Apparently-Resent-*` 系の複数 `@` 値 (再送残渣記録の addr-spec 違反) を検出 — `Envelope` に `apparently_resent_atdup` を追加。
### Security — D2270: `X-Original-Rcpt-To:` 系の複数 `@` 値 (元受取人記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_rcpt_to_atdup` を追加。
### Security — D2263: `X-Original-Cc:` の複数 `@` 値 (元副宛記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_cc_atdup` を追加。
### Security — D2264: `X-Original-Reply-To:` の複数 `@` 値 (元返信口記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_reply_to_atdup` を追加。
### Security — D2265: `Disposition-Notification-To:` の複数 `@` 値 (開封通知先記録の addr-spec 違反) を検出 — `Envelope` に `disposition_to_atdup` を追加。
### Security — D2266: `Return-Receipt-To:` の複数 `@` 値 (受領通知先記録の addr-spec 違反) を検出 — `Envelope` に `return_receipt_atdup` を追加。
### Security — D2259: `Apparently-To:` 系の複数 `@` 値 (見せ宛記録の addr-spec 違反) を検出 — `Envelope` に `apparently_to_atdup` を追加。
### Security — D2260: `Apparently-From:`/`Apparently-Sender:` 系の複数 `@` 値 (表差出人記録の addr-spec 違反) を検出 — `Envelope` に `apparently_from_atdup` を追加。
### Security — D2261: `X-Original-To:` の複数 `@` 値 (元宛先記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_to_atdup` を追加。
### Security — D2262: `X-Original-From:` の複数 `@` 値 (元差出人記録の addr-spec 違反) を検出 — `Envelope` に `x_orig_from_atdup` を追加。
### Security — D2255: `Envelope-To:` 系の複数 `@` 値 (封書宛先記録の addr-spec 違反) を検出 — `Envelope` に `env_to_atdup` を追加。
### Security — D2256: `Delivered-To:` の複数 `@` 値 (配達記録の addr-spec 違反) を検出 — `Envelope` に `delivered_to_atdup` を追加。
### Security — D2257: `X-Envelope-From:` 系の複数 `@` 値 (封書差出人記録の addr-spec 違反) を検出 — `Envelope` に `env_from_atdup` を追加。
### Security — D2258: `Errors-To:` の複数 `@` 値 (返送先記録の addr-spec 違反) を検出 — `Envelope` に `errors_to_atdup` を追加。
### Security — D2251: `X-Confirm-Reading-To:` のドット配置違反値 (閲覧確認先記録の dot-atom 違反) を検出 — `Envelope` に `confirm_reading_dotmal` を追加。
### Security — D2252: `Resent-Reply-To:` のドット配置違反値 (再送返信口記録の dot-atom 違反) を検出 — `Envelope` に `resent_reply_to_dotmal` を追加。
### Security — D2253: `Apparently-Resent-*` 系のドット配置違反値 (再送残渣記録の dot-atom 違反) を検出 — `Envelope` に `apparently_resent_dotmal` を追加。
### Security — D2254: `X-Original-Rcpt-To:` 系のドット配置違反値 (元受取人記録の dot-atom 違反) を検出 — `Envelope` に `x_orig_rcpt_to_dotmal` を追加。
### Security — D2247: `X-Original-Cc:` のドット配置違反値 (元副宛記録の dot-atom 違反) を検出 — `Envelope` に `x_orig_cc_dotmal` を追加。
### Security — D2248: `X-Original-Reply-To:` のドット配置違反値 (元返信口記録の dot-atom 違反) を検出 — `Envelope` に `x_orig_reply_to_dotmal` を追加。
### Security — D2249: `Disposition-Notification-To:` のドット配置違反値 (開封通知先記録の dot-atom 違反) を検出 — `Envelope` に `disposition_to_dotmal` を追加。
### Security — D2250: `Return-Receipt-To:` のドット配置違反値 (受領通知先記録の dot-atom 違反) を検出 — `Envelope` に `return_receipt_dotmal` を追加。
### Security — D2243: `Apparently-To:`/`X-Apparently-To:` のドット配置違反値 (見せ宛記録の dot-atom 違反) を検出 — `Envelope` に `apparently_to_dotmal` を追加。
### Security — D2244: `Apparently-From:`/`Apparently-Sender:` 系のドット配置違反値 (表差出人記録の dot-atom 違反) を検出 — `Envelope` に `apparently_from_dotmal` を追加。
### Security — D2245: `X-Original-To:` のドット配置違反値 (元宛先記録の dot-atom 違反) を検出 — `Envelope` に `x_orig_to_dotmal` を追加。
### Security — D2246: `X-Original-From:` のドット配置違反値 (元差出人記録の dot-atom 違反) を検出 — `Envelope` に `x_orig_from_dotmal` を追加。
### Security — D2239: `Envelope-To:`/`X-Envelope-To:` のドット配置違反値 (`a..b@x`/`a@.x` 形) を検出 — `Envelope` に `env_to_dotmal` を追加。
### Security — D2240: `Delivered-To:` のドット配置違反値 (配達記録の dot-atom 違反) を検出 — `Envelope` に `delivered_to_dotmal` を追加。
### Security — D2241: `X-Envelope-From:`/`X-MailFrom:` 系のドット配置違反値 (封書差出人記録の dot-atom 違反) を検出 — `Envelope` に `env_from_dotmal` を追加。
### Security — D2242: `Errors-To:` のドット配置違反値 (返送先記録の dot-atom 違反) を検出 — `Envelope` に `errors_to_dotmal` を追加。
### Security — D2235: `X-Confirm-Reading-To:` の空白入り宛名値 (閲覧確認先記録の空白形) を検出 — `Envelope` に `confirm_reading_spaced` を追加。
### Security — D2236: `Resent-Reply-To:` の空白入り宛名値 (再送返信口記録の空白形) を検出 — `Envelope` に `resent_reply_to_spaced` を追加。
### Security — D2237: `Apparently-Resent-*:` 系の空白入り宛名値 (再送残渣記録の空白形) を検出 — `Envelope` に `apparently_resent_spaced` を追加。
### Security — D2238: `X-Original-Rcpt-To:` 系の空白入り宛名値 (元受取人記録の空白形) を検出 — `Envelope` に `x_orig_rcpt_to_spaced` を追加。
### Security — D2231: `X-Original-Cc:` の空白入り宛名値 (元副宛記録の空白形) を検出 — `Envelope` に `x_orig_cc_spaced` を追加。
### Security — D2232: `X-Original-Reply-To:` の空白入り宛名値 (元返信口記録の空白形) を検出 — `Envelope` に `x_orig_reply_to_spaced` を追加。
### Security — D2233: `Disposition-Notification-To:` の空白入り宛名値 (開封通知先記録の空白形) を検出 — `Envelope` に `disposition_to_spaced` を追加。
### Security — D2234: `Return-Receipt-To:` の空白入り宛名値 (受領通知先記録の空白形) を検出 — `Envelope` に `return_receipt_spaced` を追加。
### Security — D2227: `Apparently-To:`/`X-Apparently-To:` の空白入り宛名値 (見せ宛記録の空白形) を検出 — `Envelope` に `apparently_to_spaced` を追加。
### Security — D2228: `Apparently-From:`/`Apparently-Sender:` 系の空白入り宛名値 (表差出人記録の空白形) を検出 — `Envelope` に `apparently_from_spaced` を追加。
### Security — D2229: `X-Original-To:` の空白入り宛名値 (元宛先記録の空白形) を検出 — `Envelope` に `x_orig_to_spaced` を追加。
### Security — D2230: `X-Original-From:` の空白入り宛名値 (元差出人記録の空白形) を検出 — `Envelope` に `x_orig_from_spaced` を追加。
### Security — D2223: `Envelope-To:`/`X-Envelope-To:` の空白入り宛名値 (`a @x` 形) を検出 — `Envelope` に `env_to_spaced` を追加。
### Security — D2224: `Delivered-To:` の空白入り宛名値 (配達記録の空白形) を検出 — `Envelope` に `delivered_to_spaced` を追加。
### Security — D2225: `X-Envelope-From:`/`X-MailFrom:` 系の空白入り宛名値 (封書差出人記録の空白形) を検出 — `Envelope` に `env_from_spaced` を追加。
### Security — D2226: `Errors-To:` の空白入り宛名値 (返送先記録の空白形) を検出 — `Envelope` に `errors_to_spaced` を追加。
### Security — D2219: `X-Confirm-Reading-To:` の括弧・引用囲い値 (閲覧確認先記録の囲い形) を検出 — `Envelope` に `confirm_reading_bracketed` を追加。
### Security — D2220: `Resent-Reply-To:` の括弧・引用囲い値 (再送返信口記録の囲い形) を検出 — `Envelope` に `resent_reply_to_bracketed` を追加。
### Security — D2221: `Apparently-Resent-*:` 系の括弧・引用囲い値 (再送残渣記録の囲い形) を検出 — `Envelope` に `apparently_resent_bracketed` を追加。
### Security — D2222: `X-Original-Rcpt-To:` 系の括弧・引用囲い値 (元受取人記録の囲い形) を検出 — `Envelope` に `x_orig_rcpt_to_bracketed` を追加。
### Security — D2215: `X-Original-Cc:` の括弧・引用囲い値 (元副宛記録の囲い形) を検出 — `Envelope` に `x_orig_cc_bracketed` を追加。
### Security — D2216: `X-Original-Reply-To:` の括弧・引用囲い値 (元返信口記録の囲い形) を検出 — `Envelope` に `x_orig_reply_to_bracketed` を追加。
### Security — D2217: `Disposition-Notification-To:` の括弧・引用囲い値 (開封通知先記録の囲い形) を検出 — `Envelope` に `disposition_to_bracketed` を追加。
### Security — D2218: `Return-Receipt-To:` の括弧・引用囲い値 (受領通知先記録の囲い形) を検出 — `Envelope` に `return_receipt_bracketed` を追加。
### Security — D2211: `Apparently-To:` 系の括弧・引用囲い値 (見せ宛記録の囲い形) を検出 — `Envelope` に `apparently_to_bracketed` を追加。
### Security — D2212: `Apparently-From:`/`Apparently-Sender:` 系の括弧・引用囲い値 (表差出人記録の囲い形) を検出 — `Envelope` に `apparently_from_bracketed` を追加。
### Security — D2213: `X-Original-To:` の括弧・引用囲い値 (元宛先記録の囲い形) を検出 — `Envelope` に `x_orig_to_bracketed` を追加。
### Security — D2214: `X-Original-From:` の括弧・引用囲い値 (元差出人記録の囲い形) を検出 — `Envelope` に `x_orig_from_bracketed` を追加。
### Security — D2207: `Envelope-To:` 系の括弧・引用囲い値 (生宛名記録の囲い形) を検出 — `Envelope` に `env_to_bracketed` を追加。
### Security — D2208: `Delivered-To:` の括弧・引用囲い値 (配達記録の囲い形) を検出 — `Envelope` に `delivered_to_bracketed` を追加。
### Security — D2209: `X-Envelope-From:` 系の括弧・引用囲い値 (封書差出人記録の囲い形) を検出 — `Envelope` に `env_from_bracketed` を追加。
### Security — D2210: `Errors-To:` の括弧・引用囲い値 (返送先記録の囲い形) を検出 — `Envelope` に `errors_to_bracketed` を追加。
### Security — D2203: `X-Confirm-Reading-To:` の複数値 (閲覧確認先記録のカンマ連結値) を検出 — `Envelope` に `confirm_reading_addr_list` を追加。
### Security — D2204: `Resent-Reply-To:` の複数値 (再送返信口記録のカンマ連結値) を検出 — `Envelope` に `resent_reply_to_addr_list` を追加。
### Security — D2205: `Apparently-Resent-*:` 系の複数値 (再送残渣記録のカンマ連結値) を検出 — `Envelope` に `apparently_resent_addr_list` を追加。
### Security — D2206: `X-Original-Rcpt-To:` 系の複数値 (元受取人記録のカンマ連結値) を検出 — `Envelope` に `x_orig_rcpt_to_addr_list` を追加。
### Security — D2199: `X-Original-Cc:` の複数値 (元副宛記録のカンマ連結値) を検出 — `Envelope` に `x_orig_cc_addr_list` を追加。
### Security — D2200: `X-Original-Reply-To:` の複数値 (元返信口記録のカンマ連結値) を検出 — `Envelope` に `x_orig_reply_to_addr_list` を追加。
### Security — D2201: `Disposition-Notification-To:` の複数値 (開封通知先記録のカンマ連結値) を検出 — `Envelope` に `disposition_to_addr_list` を追加。
### Security — D2202: `Return-Receipt-To:` の複数値 (受領通知先記録のカンマ連結値) を検出 — `Envelope` に `return_receipt_addr_list` を追加。
### Security — D2195: `Apparently-To:` 系の複数値 (見せ宛記録のカンマ連結値) を検出 — `Envelope` に `apparently_to_addr_list` を追加。
### Security — D2196: `Apparently-From:`/`Apparently-Sender:` 系の複数値 (表差出人記録のカンマ連結値) を検出 — `Envelope` に `apparently_from_addr_list` を追加。
### Security — D2197: `X-Original-To:` の複数値 (元宛先記録のカンマ連結値) を検出 — `Envelope` に `x_orig_to_addr_list` を追加。
### Security — D2198: `X-Original-From:` の複数値 (元差出人記録のカンマ連結値) を検出 — `Envelope` に `x_orig_from_addr_list` を追加。
### Security — D2191: `Envelope-To:` 系の複数値 (封書宛先記録のカンマ連結値) を検出 — `Envelope` に `env_to_addr_list` を追加。
### Security — D2192: `Delivered-To:` の複数値 (配達記録のカンマ連結値) を検出 — `Envelope` に `delivered_to_addr_list` を追加。
### Security — D2193: 封書差出人記録欄 (`X-Envelope-From:`/`X-MailFrom:` 等) の複数値を検出 — `Envelope` に `env_from_addr_list` を追加。
### Security — D2194: `Errors-To:` の複数値 (返送先記録のカンマ連結値) を検出 — `Envelope` に `errors_to_addr_list` を追加。
### Security — D2187: `Delivered-To:` の宛名でない値 (配達記録の非宛名値) を検出 — `Envelope` に `delivered_to_non_addr` を追加。
### Security — D2188: `Errors-To:` の宛名でない値 (返送先記録の非宛名値) を検出 — `Envelope` に `errors_to_non_addr` を追加。
### Security — D2189: `X-Original-Rcpt-To:` 系の宛名でない値 (元受取人記録の非宛名値) を検出 — `Envelope` に `x_orig_rcpt_to_non_addr` を追加。
### Security — D2190: `Apparently-Resent-*:` 系の宛名でない値 (再送残渣の非宛名値) を検出 — `Envelope` に `apparently_resent_non_addr` を追加。
### Security — D2183: `Disposition-Notification-To:` の宛名でない値 (開封通知先の非宛名値) を検出 — `Envelope` に `disposition_to_non_addr` を追加。
### Security — D2184: `Return-Receipt-To:` の宛名でない値 (受領通知先の非宛名値) を検出 — `Envelope` に `return_receipt_to_non_addr` を追加。
### Security — D2185: `X-Confirm-Reading-To:` の宛名でない値 (閲覧確認先の非宛名値) を検出 — `Envelope` に `confirm_reading_non_addr` を追加。
### Security — D2186: `Resent-Reply-To:` の宛名でない値 (再送返信口の非宛名値) を検出 — `Envelope` に `resent_reply_to_non_addr` を追加。
### Security — D2179: `X-Original-To:` の宛名でない値 (元宛先記録の非宛名値) を検出 — `Envelope` に `x_orig_to_non_addr` を追加。
### Security — D2180: `X-Original-From:` の宛名でない値 (元差出人記録の非宛名値) を検出 — `Envelope` に `x_orig_from_non_addr` を追加。
### Security — D2181: `X-Original-Cc:` の宛名でない値 (元副宛先記録の非宛名値) を検出 — `Envelope` に `x_orig_cc_non_addr` を追加。
### Security — D2182: `X-Original-Reply-To:` の宛名でない値 (元返信口記録の非宛名値) を検出 — `Envelope` に `x_orig_reply_to_non_addr` を追加。
### Security — D2175: `Envelope-To:` 系の宛名でない値 (封書宛先記録の非宛名値) を検出 — `Envelope` に `env_to_non_addr` を追加。
### Security — D2176: `Apparently-To:` 系の宛名でない値 (見せ宛記録の非宛名値) を検出 — `Envelope` に `apparently_to_non_addr` を追加。
### Security — D2177: 封書差出人記録欄 (`X-Envelope-From:`/`X-MailFrom:` 等) の宛名でない値を検出 — `Envelope` に `env_from_non_addr` を追加。
### Security — D2178: `Apparently-From:`/`Apparently-Sender:` 系の宛名でない値 (表差出人記録の非宛名値) を検出 — `Envelope` に `apparently_from_non_addr` を追加。
### Security — D2171: `Authentication-Results:` 系の空値 (認証結果欄の空欄) を検出 — `Envelope` に `auth_results_empty` を追加。
### Security — D2172: `DKIM-Signature:` の空値 (署名欄の空欄) を検出 — `Envelope` に `dkim_sig_empty` を追加。
### Security — D2173: `Received-SPF:` の空値 (SPF判定欄の空欄) を検出 — `Envelope` に `received_spf_empty` を追加。
### Security — D2174: 優先度欄 (`X-Priority:`/`X-MSMail-Priority:`/`Priority:`/`Importance:`) の空値を検出 — `Envelope` に `priority_headers_empty` を追加。
### Security — D2167: `X-Original-To-Headers:` の空値 (元宛先欄記録の空欄) を検出 — `Envelope` に `x_orig_to_headers_empty` を追加。
### Security — D2168: `X-Original-Rcpt-To:` 系の空値 (元受取人記録の空欄) を検出 — `Envelope` に `x_orig_rcpt_to_empty` を追加。
### Security — D2169: `X-Original-Authentication-Results:` の空値 (元認証結果記録の空欄) を検出 — `Envelope` に `x_orig_ar_empty` を追加。
### Security — D2170: `X-OriginalArrivalTime:` 系の空値 (元到着時刻記録の空欄) を検出 — `Envelope` に `x_orig_arrival_empty` を追加。
### Security — D2163: `X-Original-Bcc:` の空値 (元隠し宛先記録の空欄) を検出 — `Envelope` に `x_orig_bcc_empty` を追加。
### Security — D2164: `Fcc:`/`X-Fcc:` の空値 (送信控え欄の空欄) を検出 — `Envelope` に `fcc_empty` を追加。
### Security — D2165: `X-Forwarded-*` 群の空値 (転送元記録の空欄) を検出 — `Envelope` に `x_forwarded_empty` を追加。
### Security — D2166: `Apparently-Resent-*` 群の空値 (再送残渣記録の空欄) を検出 — `Envelope` に `apparently_resent_empty` を追加。
### Security — D2159: `X-Original-Cc:` の空値 (元副宛先記録の空欄) を検出 — `Envelope` に `x_orig_cc_empty` を追加。
### Security — D2160: `X-Original-Reply-To:` の空値 (元返信口記録の空欄) を検出 — `Envelope` に `x_orig_reply_to_empty` を追加。
### Security — D2161: `X-Original-Date:` の空値 (元日時記録の空欄) を検出 — `Envelope` に `x_orig_date_empty` を追加。
### Security — D2162: `X-Original-References:` の空値 (元糸参照記録の空欄) を検出 — `Envelope` に `x_orig_refs_empty` を追加。
### Security — D2155: `X-Original-To:` の空値 (元受取人記録の空欄) を検出 — `Envelope` に `x_orig_to_empty` を追加。
### Security — D2156: `X-Original-From:` の空値 (元差出人記録の空欄) を検出 — `Envelope` に `x_orig_from_empty` を追加。
### Security — D2157: `X-Original-Message-ID:` の空値 (元識別子記録の空欄) を検出 — `Envelope` に `x_orig_msgid_empty` を追加。
### Security — D2158: `X-Original-Subject:` の空値 (元件名記録の空欄) を検出 — `Envelope` に `x_orig_subject_empty` を追加。
### Security — D2151: `Disposition-Notification-To:` の空値 (開封通知要求先の空欄) を検出 — `Envelope` に `disposition_to_empty` を追加。
### Security — D2152: `Return-Receipt-To:` の空値 (旧式受領通知要求先の空欄) を検出 — `Envelope` に `return_receipt_to_empty` を追加。
### Security — D2153: `X-Confirm-Reading-To:` の空値 (旧式閲覧確認要求先の空欄) を検出 — `Envelope` に `confirm_reading_empty` を追加。
### Security — D2154: `Resent-Reply-To:` の空値 (旧式再送返信口の空欄) を検出 — `Envelope` に `resent_reply_to_empty` を追加。
### Security — D2147: `Envelope-To:`/`X-Envelope-To:` の空値 (封書受取人記録の空欄) を検出 — `Envelope` に `env_to_empty` を追加。
### Security — D2148: `Apparently-To:`/`X-Apparently-To:` の空値 (見せかけ宛先記録の空欄) を検出 — `Envelope` に `apparently_to_empty` を追加。
### Security — D2149: `X-Envelope-From:` 等エンベロープ差出人記録欄の空値 (封書差出人記録の空欄) を検出 — `Envelope` に `env_from_empty` を追加。
### Security — D2150: `Apparently-From:`/`Apparently-Sender:` 系の空値 (表差出人記録の空欄) を検出 — `Envelope` に `apparently_from_empty` を追加。
### Security — D2143: `Disposition-Notification-To:` の重複出現 (開封通知要求先の多重化) を検出 — `Envelope` に `multi_disposition_to` を追加。
### Security — D2144: `Return-Receipt-To:` の重複出現 (旧式受領通知要求先の多重化) を検出 — `Envelope` に `multi_return_receipt_to` を追加。
### Security — D2145: `X-Confirm-Reading-To:` の重複出現 (旧式閲覧確認要求先の多重化) を検出 — `Envelope` に `multi_confirm_reading` を追加。
### Security — D2146: `Resent-Reply-To:` の重複出現 (旧式再送返信口の多重化) を検出 — `Envelope` に `multi_resent_reply_to` を追加。
### Security — D2139: `X-Original-Cc:` の重複出現 (元副宛先書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_cc` を追加。
### Security — D2140: `X-Original-Reply-To:` の重複出現 (元返信口書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_reply_to` を追加。
### Security — D2141: `X-Original-Date:` の重複出現 (元日時書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_date` を追加。
### Security — D2142: `X-Original-References:` の重複出現 (元糸参照書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_refs` を追加。
### Security — D2135: `X-Original-To:` の重複出現 (元宛先書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_to` を追加。
### Security — D2136: `X-Original-From:` の重複出現 (元差出人書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_from` を追加。
### Security — D2137: `X-Original-Message-ID:` の重複出現 (元識別子書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_msgid` を追加。
### Security — D2138: `X-Original-Subject:` の重複出現 (元件名書き換え記録の多重化) を検出 — `Envelope` に `multi_x_orig_subject` を追加。
### Security — D2131: `Envelope-To:`/`X-Envelope-To:` の重複出現 (封書受取人記録の多重化で先頭/末尾/一覧読みが分かれる形) を検出 — `Envelope` に `multi_env_to` を追加。
### Security — D2132: `Apparently-To:`/`X-Apparently-To:` の重複出現 (見せかけ宛先記録の多重化) を検出 — `Envelope` に `multi_apparently_to` を追加。
### Security — D2133: `X-Envelope-From:` 等エンベロープ差出人記録欄の重複出現 (封書差出人記録の多重化) を検出 — `Envelope` に `multi_env_from` を追加。
### Security — D2134: `Apparently-From:`/`Apparently-Sender:` 系の重複出現 (sendmail 差出人記録の多重化) を検出 — `Envelope` に `multi_apparently_from` を追加。
### Security — D2127: `Return-Path:` と `X-Envelope-From:` 等のエンベロープ差出人記録の不一致アドレス (二つの配送記録の食い違い) を検出 — `Envelope` に `return_path_differs_env_from` を追加。
### Security — D2128: `Return-Path:` と `Apparently-From:`/`Apparently-Sender:` 系の不一致アドレス (返送先と sendmail 差出人記録の食い違い) を検出 — `Envelope` に `return_path_differs_apparently_from` を追加。
### Security — D2129: `X-Envelope-From:` 等のエンベロープ差出人記録と `Apparently-From:` 系の不一致アドレス (二つの差出人記録の食い違い) を検出 — `Envelope` に `env_from_differs_apparently_from` を追加。
### Security — D2130: `X-Original-From:` と `X-Envelope-From:` 等のエンベロープ差出人記録の不一致アドレス (元差出人記録と封書記録の食い違い) を検出 — `Envelope` に `x_orig_from_differs_env_from` を追加。
### Security — D2123: `X-Original-To:` と `Apparently-To:` の不一致アドレス (二つの「元の受取人」記録の食い違い) を検出 — `Envelope` に `x_orig_to_differs_apparently_to` を追加。
### Security — D2124: `X-Original-To:` と `Envelope-To:` の不一致アドレス (エイリアス展開記録とエンベロープ記録の食い違い) を検出 — `Envelope` に `x_orig_to_differs_envelope_to` を追加。
### Security — D2125: `Envelope-To:` と `Delivered-To:` の不一致アドレス (エンベロープ記録と最終配達記録の食い違い) を検出 — `Envelope` に `envelope_to_differs_delivered_to` を追加。
### Security — D2126: `Envelope-To:` と `Apparently-To:` の不一致アドレス (エンベロープ記録と見せかけ宛先記録の食い違い) を検出 — `Envelope` に `envelope_to_differs_apparently_to` を追加。
### Security — D2119: `X-Original-Sender:` と `Sender:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_sender_same_as_sender` を追加。
### Security — D2120: `X-Original-Cc:` と `Cc:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_cc_same_as_cc` を追加。
### Security — D2121: `X-Original-Reply-To:` と `Reply-To:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_reply_to_same_as_reply_to` を追加。
### Security — D2122: `X-Original-References:` と `References:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_refs_same_as_refs` を追加。
### Security — D2115: `X-Original-From:` と `From:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_from_same_as_from` を追加。
### Security — D2116: `X-Original-Subject:` と `Subject:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_subject_same_as_subject` を追加。
### Security — D2117: `X-Original-Message-ID:` と `Message-ID:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_msgid_same_as_msgid` を追加。
### Security — D2118: `X-Original-Date:` と `Date:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_date_same_as_date` を追加。
### Security — D2111: `Fcc:`/`X-Fcc:` (差出控えの格納欄の残渣) を検出 — `Envelope` に `fcc_mark` を追加。
### Security — D2112: `X-Forwarded-*` 群 (転送元情報の残渣欄) を検出 — `Envelope` に `forwarded_marks` を追加。
### Security — D2113: `Apparently-To:`/`X-Apparently-To:` と `To:` の一致 (受取欄不在時のみ記されるべき記録の矛盾) を検出 — `Envelope` に `apparently_to_same_as_to` を追加。
### Security — D2114: `X-Original-To:` と `To:` の一致 (書き換えたはずの記録の矛盾) を検出 — `Envelope` に `x_orig_to_same_as_to` を追加。
### Security — D2107: `Apparently-Resent-To:`/`Apparently-Resent-From:`/`Apparently-Resent-Sender:` (sendmail 再送モードの残渣欄) を検出 — `Envelope` に `apparently_resent_marks` を追加。
### Security — D2108: `X-Original-Bcc:` (改変前の隠し宛先の記録欄露出) を検出 — `Envelope` に `x_orig_bcc_mark` を追加。
### Security — D2109: `X-Original-Cc:` (改変前の副宛先の記録欄露出) を検出 — `Envelope` に `x_orig_cc_mark` を追加。
### Security — D2110: `X-Original-Reply-To:` (改変前の返信口の記録欄露出) を検出 — `Envelope` に `x_orig_reply_to_mark` を追加。
### Security — D2103: `X-Envelope-From:`/`X-Original-Sender:` 等のエンベロープ差出人記録と `From:` の不一致アドレスを検出 — `Envelope` に `env_from_differs_from` を追加。
### Security — D2104: `Apparently-From:`/`Apparently-Sender:` 等の sendmail 差出人記録と `From:` の不一致アドレスを検出 — `Envelope` に `apparently_from_differs_from` を追加。
### Security — D2105: `Return-Receipt-To:` と `Reply-To:` の不一致アドレス (受領通知が返信口と別口へ向かう追跡ループ) を検出 — `Envelope` に `rrt_differs_reply_to` を追加。
### Security — D2106: `X-Confirm-Reading-To:` と `Reply-To:` の不一致アドレス (閲覧確認が返信口と別口へ向かう追跡ループ) を検出 — `Envelope` に `xrt_differs_reply_to` を追加。
### Security — D2099: `Apparently-To:` と `To:` の不一致アドレス (実受取人記録と宛先欄の分離) を検出 — `Envelope` に `apparently_to_differs_to` を追加。
### Security — D2100: `Apparently-To:` と `Delivered-To:` の不一致アドレス (sendmail 記録と MTA 配達記録の食い違い) を検出 — `Envelope` に `apparently_to_differs_delivered_to` を追加。
### Security — D2101: `X-Original-To:` と `Delivered-To:` の不一致アドレス (エイリアス展開記録と最終配達記録の食い違い) を検出 — `Envelope` に `x_orig_to_differs_delivered_to` を追加。
### Security — D2102: `Resent-Reply-To:` と `Reply-To:` の不一致アドレス (旧式再送返信欄と現返信口の食い違い) を検出 — `Envelope` に `resent_reply_to_differs_reply_to` を追加。
### Security — D2095: `Disposition-Notification-To:` と `From:` の不一致アドレス (開封通知が別の受取口へ向かう追跡ループ) を検出 — `Envelope` に `dnt_differs_from` を追加。
### Security — D2096: `Return-Receipt-To:` と `From:` の不一致アドレス (旧式受領通知が別の受取口へ向かう追跡ループ) を検出 — `Envelope` に `rrt_differs_from` を追加。
### Security — D2097: `X-Confirm-Reading-To:` と `From:` の不一致アドレス (旧式閲覧確認が別の受取口へ向かう追跡ループ) を検出 — `Envelope` に `xrt_differs_from` を追加。
### Security — D2098: `Disposition-Notification-To:` と `Reply-To:` の不一致アドレス (開封通知が返信口と別口へ向かう追跡ループ) を検出 — `Envelope` に `dnt_differs_reply_to` を追加。
### Security — D2091: `X-Original-To:` と `To:` の不一致アドレス (エイリアス展開前の元受取人記録と表示宛先の分離) を検出 — `Envelope` に `x_orig_to_differs` を追加。
### Security — D2092: `X-Original-Cc:` と `Cc:` の不一致アドレス (元の副宛先記録と表示副宛先の分離) を検出 — `Envelope` に `x_orig_cc_differs` を追加。
### Security — D2093: `X-Original-Sender:` と `Sender:` の不一致アドレス (元の代行記録と表示代行者の分離) を検出 — `Envelope` に `x_orig_sender_differs` を追加。
### Security — D2094: `X-Original-References:` と `References:` の不一致値 (元の糸参照記録と現参照一覧の分離) を検出 — `Envelope` に `x_orig_refs_differs` を追加。
### Security — D2087: `X-Original-From:` と `From:` の不一致アドレス (元の差出人記録と表示差出人の分離) を検出 — `Envelope` に `x_orig_from_differs` を追加。
### Security — D2088: `X-Original-Subject:` と `Subject:` の不一致値 (元の件名記録と表示件名の分離) を検出 — `Envelope` に `x_orig_subject_differs` を追加。
### Security — D2089: `X-Original-Message-ID:` と `Message-ID:` の不一致識別子 (元の識別子記録と現識別子の分離) を検出 — `Envelope` に `x_orig_msgid_differs` を追加。
### Security — D2090: `X-Original-Date:` と `Date:` の不一致値 (元の日時記録と表示日時の分離) を検出 — `Envelope` に `x_orig_date_differs` を追加。
### Security — D2083: `Delivered-To:` と `From:` の同一アドレス (自分へ戻る配送) を検出 — `Envelope` に `delivered_to_same_as_from` を追加。
### Security — D2084: `Delivered-To:` と `Reply-To:` の同一アドレス (宛名・返信口・実配の畳み) を検出 — `Envelope` に `delivered_to_same_as_reply_to` を追加。
### Security — D2085: `Envelope-To:`/`X-Envelope-To:` と `Cc:` の同一アドレスを検出 — `Envelope` に `envelope_to_same_as_cc` を追加 (`delivered_to_same_as_cc` の派生欄版)。
### Security — D2086: `Delivered-To:` と `Sender:` の同一アドレス (代行宛の配送) を検出 — `Envelope` に `delivered_to_same_as_sender` を追加。
### Security — D2079: `Delivered-To:` と `To:` の相違アドレス (宛名の化粧) を検出 — `Envelope` に `delivered_to_differs_to` を追加。
### Security — D2080: `Envelope-To:`/`X-Envelope-To:` と `To:` の相違アドレスを検出 — `Envelope` に `envelope_to_differs_to` を追加 (`delivered_to_differs_to` の派生欄版)。
### Security — D2081: `Delivered-To:` と `Cc:` の同一アドレス (実配達先が副宛) を検出 — `Envelope` に `delivered_to_same_as_cc` を追加。
### Security — D2082: `Return-Path:` と `From:` の相違アドレス (返送先と表示差出人の分離) を検出 — `Envelope` に `return_path_differs_from` を追加。
### Security — D2075: `Reply-To:` と `Cc:` の同一アドレス (副宛への返信) を検出 — `Envelope` に `reply_to_same_as_cc` を追加。
### Security — D2076: `Sender:` と `To:` の同一アドレス (宛先と同一の代行) を検出 — `Envelope` に `sender_same_as_to` を追加。
### Security — D2077: `Sender:` と `Cc:` の同一アドレス (副宛と同一の代行) を検出 — `Envelope` に `sender_same_as_cc` を追加。
### Security — D2078: `From:` と `Cc:` の同一アドレス (副宛と同一の差出人) を検出 — `Envelope` に `from_same_as_cc` を追加。
### Security — D2071: `To:` と `Cc:` の同一アドレス (受取役割の重複) を検出 — `Envelope` に `to_same_as_cc` を追加 (`same_addr_dup` の欄間版)。
### Security — D2072: `Reply-To:` と `To:` の同一アドレス (受取人への返信ループ) を検出 — `Envelope` に `reply_to_same_as_to` を追加。
### Security — D2073: `From:` と `To:` の同一アドレス (自己送信) を検出 — `Envelope` に `from_same_as_to` を追加。
### Security — D2074: `Reply-To:` と `Sender:` の同一アドレス (代行への返信) を検出 — `Envelope` に `reply_to_same_as_sender` を追加。
### Security — D2067: `Resent-Cc:` と `To:` の同一アドレス (主宛先の副宛への降格) を検出 — `Envelope` に `resent_cc_same_as_to` を追加 (`resent_to_same_as_cc` の逆方向)。
### Security — D2068: `Resent-Cc:` と `From:` の同一アドレス (差出人宛の副宛再送) を検出 — `Envelope` に `resent_cc_same_as_from` を追加 (`resent_to_same_as_from` の副宛版)。
### Security — D2069: `Resent-To:` と `Resent-Sender:` の同一アドレス (再送代行宛の再送) を検出 — `Envelope` に `resent_to_same_as_resent_sender` を追加。
### Security — D2070: `Resent-Cc:` と `Resent-Sender:` の同一アドレスを検出 — `Envelope` に `resent_cc_same_as_resent_sender` を追加。
### Security — D2063: `Resent-To:` と `Resent-From:` の同一アドレス (自己への再送) を検出 — `Envelope` に `resent_to_same_as_resent_from` を追加。
### Security — D2064: `Resent-Cc:` と `Resent-From:` の同一アドレスを検出 — `Envelope` に `resent_cc_same_as_resent_from` を追加。
### Security — D2065: `Resent-Sender:` と `Resent-From:` の同一アドレス (再送ブロック内の冗長代行) を検出 — `Envelope` に `resent_sender_same_as_resent_from` を追加 (`from_sender_dup` の再送版)。
### Security — D2066: `Resent-Cc:` と `Resent-To:` の同一アドレス (再送ブロック内の役割重複) を検出 — `Envelope` に `resent_cc_same_as_resent_to` を追加。
### Security — D2059: `Resent-Cc:` と `Cc:` の同一アドレスを検出 — `Envelope` に `resent_cc_same_as_cc` を追加 (再送同一値系の補完)。
### Security — D2060: `Resent-To:` と `Cc:` の同一アドレス (副宛先の格上げ) を検出 — `Envelope` に `resent_to_same_as_cc` を追加。
### Security — D2061: `Resent-From:` と `Sender:` の同一アドレスを検出 — `Envelope` に `resent_from_same_as_sender` を追加。
### Security — D2062: `Resent-Sender:` と `From:` の同一アドレスを検出 — `Envelope` に `resent_sender_same_as_from` を追加。
### Security — D2055: `Resent-To:` と `To:` の同一アドレスを検出 — `Envelope` に `resent_to_same_as_to` を追加 (`resent_from_same_as_from` の補完)。
### Security — D2056: `Resent-To:` と `From:` の同一アドレス (差出人への再送) を検出 — `Envelope` に `resent_to_same_as_from` を追加。
### Security — D2057: `Resent-Sender:` と `Sender:` の同一アドレスを検出 — `Envelope` に `resent_sender_same_as_sender` を追加。
### Security — D2058: `Resent-Date:` と `Date:` の同一値を検出 — `Envelope` に `resent_date_same_as_date` を追加。
### Security — D2051: `Sender:` と `From:` の同一アドレスを検出 — `Envelope` に `from_sender_dup` を追加 (`sender_no_from` の補完)。
### Security — D2052: `Reply-To:` と `From:` の同一アドレスを検出 — `Envelope` に `reply_to_same_as_from` を追加 (複数値の `multi_reply_to` の補完)。
### Security — D2053: `In-Reply-To:` あるのに `References:` 無しを検出 — `Envelope` に `irt_no_refs` を追加 (糸参照値異常の `refs_*` 系の補完)。
### Security — D2054: `Resent-From:` と `From:` の同一アドレスを検出 — `Envelope` に `resent_from_same_as_from` を追加 (`resent_msgid_same` の補完)。
### Security — D2047: `Resent-*` ブロックの `Resent-Message-ID:` 欠落を検出 — `Envelope` に `resent_no_msgid` を追加 (必須欄欠落の D1476・受取欄欠落の D2045 の補完)。
### Security — D2048: msgid 系欄の大小文字違いの同一識別子反復を検出 — `Envelope` に `msgid_case_variant_pair` を追加 (完全一致反復の D2038・refs 側の D1697 の補完)。
### Security — D2049: 外側メッセージ欄の `Content-ID:` を検出 — `Envelope` に `content_id_top` を追加 (部品側異常の D1532・重複の D1369・参照先欠落の D1467 の補完)。
### Security — D2050: 宛先系欄の宛先数過剰 (50 件超) を検出 — `Envelope` に `to_many_addrs` を追加 (空要素の D1366・宛先欠落の D1417 の補完)。
### Security — D2046: 非規格 `Resent-*` 欄名を検出 — `Envelope` に `resent_unknown_field` を追加 (D2042 `resent_reply_to` の補完)。
### Security — D2039: `References:` 末尾識別子と `In-Reply-To:` の食い違いを検出 — `Envelope` に `refs_irt_conflict` を追加 (糸参照系 D1449/`malformed_thread_refs` の補完)。
### Withdrawn — D2040: `refs_self_reference` は既存 D1379 `self_reply_ref` と同一仕様のため撤回 (重複検出器を除去)。
### Security — D2041: `Resent-Message-ID:` と `Message-ID:` の同一識別子を検出 — `Envelope` に `resent_msgid_same` を追加 (D1476 `incomplete_resent`・D1428 `resent_bcc` の補完)。
### Security — D2042: 旧式欄 `Resent-Reply-To:` の残存を検出 — `Envelope` に `resent_reply_to` を追加 (Resent 系 D1476/D1428 の補完)。
### Security — D2038: `Message-ID:` 系欄 (refs 以外) の同一 `<id>` 反復を検出 — `Envelope` に `msgid_dup_pair` を追加 (`msgid_ref_dup`/`multi_inreply` と役割分担)。
### Security — D2037: `Message-ID:` 系欄の値が完全に空を検出 — `Envelope` に `msgid_empty_value` を追加 (裸値は `msgid_no_angle`/`bare_msgid_ref`)。
### Security — D2036: `Message-ID:` 系欄の `<a> w <b>` 対間の語を検出 — `Envelope` に `msgid_word_between_angles` を追加 (In-Reply-To は `multi_inreply`、末尾残滓は `junk_after_angle`)。
### Security — D2035: `Message-ID:` 系欄 (refs 以外) の `<a><b>` 連結を検出 — `Envelope` に `msgid_adjacent_angles` を追加 (References は `refs_adjacent_angles`、In-Reply-To は `multi_inreply`)。
### Security — D2034: `Message-ID:` 系欄の `<…>` 内側の非隣接 `<` を検出 — `Envelope` に `msgid_inner_lt` を追加 (`<<` 直結は `nested_msgid`)。
### Security — D2033: `Message-ID:` 系欄の `<…>` 内側の `;` を検出 — `Envelope` に `msgid_inner_semi` を追加 (内側の `|`/`\`/`?`/`&`/`'`/`=`/`:`/`/`/`,` は `msgid_bad_char`)。
### Security — D2032: `Message-ID:` 系欄の `<…>` 内側の `}` を検出 — `Envelope` に `msgid_inner_rbrace` を追加 (同上)。
### Security — D2031: `Message-ID:` 系欄の `<…>` 内側の `{` を検出 — `Envelope` に `msgid_inner_lbrace` を追加 (同上)。
### Security — D2030: `Message-ID:` 系欄の `<…>` 内側の `~` を検出 — `Envelope` に `msgid_inner_tilde` を追加 (内側の `|`/`\`/`?`/`&`/`'`/`=`/`:`/`/`/`,` は `msgid_bad_char`、`!`/`#`/`$`/`*` は D2023–D2026)。
### Security — D2029: `Message-ID:` 系欄の `<…>` 内側の `` ` `` を検出 — `Envelope` に `msgid_inner_backtick` を追加 (同上)。
### Security — D2028: `Message-ID:` 系欄の `<…>` 内側の `^` を検出 — `Envelope` に `msgid_inner_caret` を追加 (同上)。
### Security — D2027: `Message-ID:` 系欄の `<…>` 内側の `%` を検出 — `Envelope` に `msgid_inner_pct` を追加 (同上)。
### Security — D2026: `Message-ID:` 系欄の `<…>` 内側の `*` を検出 — `Envelope` に `msgid_inner_star` を追加 (内側の `|`/`\`/`?`/`&`/`'`/`=`/`:`/`/`/`,` は `msgid_bad_char`)。
### Security — D2025: `Message-ID:` 系欄の `<…>` 内側の `$` を検出 — `Envelope` に `msgid_inner_dollar` を追加 (同上)。
### Security — D2024: `Message-ID:` 系欄の `<…>` 内側の `#` を検出 — `Envelope` に `msgid_inner_hash` を追加 (同上)。
### Security — D2023: `Message-ID:` 系欄の `<…>` 内側の `!` を検出 — `Envelope` に `msgid_inner_bang` を追加 (同上)。
### Security — D2022: `Message-ID:` 系欄 (`message-id`/`resent-message-id`/`list-id`/`content-id`) の `<` を欠く値を検出 — `Envelope` に `msgid_no_angle` を追加 (`In-Reply-To`/`References` の裸値は `bare_msgid_ref`)。
### Security — D2021: `Message-ID:` 系欄の最初の `<` より前の英数字語を検出 — `Envelope` に `msgid_junk_before_angle` を追加 (`References`/`In-Reply-To` 側は `refs_junk_before_angle`)。
### Security — D2020: `Message-ID:` 系欄の値頭の `\` を検出 — `Envelope` に `msgid_bslash_lead` を追加 (これで値頭の表示可能な特殊字は `msgid_*_lead` 系で全網羅)。
### Security — D2019: `Message-ID:` 系欄の値頭の `*` を検出 — `Envelope` に `msgid_star_lead` を追加。
### Security — D2018: `References:` の識別子直後に続く `<…>` を検出 — `Envelope` に `refs_adjacent_angles` を追加 (`<<`/`>>` 入れ子は `nested_msgid`、`In-Reply-To` の複数識別子は `multi_inreply`)。
### Security — D2017: `References:`/`In-Reply-To:` の識別子より前に閉じたコメントを検出 — `Envelope` に `refs_comment_before_msgid` を追加 (`)<` 直結は `msgid_paren`、コメント内識別子は `refs_comment_lead`)。
### Security — D2016: `References:`/`In-Reply-To:` の最初の `<` より前の英数字語を検出 — `Envelope` に `refs_junk_before_angle` を追加 (前置特殊字は `refs_*_lead` 系)。
### Security — D2015: `References:`/`In-Reply-To:` の値頭の `\` を検出 — `Envelope` に `refs_bslash_lead` を追加 (これで値頭の表示可能な特殊字は D1991–D2015 で全網羅)。
### Security — D2014: `References:`/`In-Reply-To:` の値頭の `.` を検出 — `Envelope` に `refs_dot_lead` を追加 (値頭の `;`/`,`/`>`/`(`/`"`/`!`/`=`/`:`/`*`/`#`/`$`/`@`/`?`/`&`/`'`/`+`/`/`/`%`/`-`/`[`/`]`/`^`/`_`/`` ` ``/`~` は `ref_lead_sep`/`ref_gt_lead`/`refs_comment_lead` 及び D1991–D2010)。
### Security — D2013: `References:`/`In-Reply-To:` の値頭の `}` を検出 — `Envelope` に `refs_rbrace_lead` を追加 (同上)。
### Security — D2012: `References:`/`In-Reply-To:` の値頭の `|` を検出 — `Envelope` に `refs_pipe_lead` を追加 (同上)。
### Security — D2011: `References:`/`In-Reply-To:` の値頭の `{` を検出 — `Envelope` に `refs_lbrace_lead` を追加 (同上)。
### Security — D2010: `References:`/`In-Reply-To:` の値頭の `~` を検出 — `Envelope` に `refs_tilde_lead` を追加 (値頭の `;`/`,`/`>`/`(`/`"`/`!`/`=`/`:`/`*`/`#`/`$`/`@`/`?`/`&`/`'`/`+`/`/`/`%`/`-`/`[`/`]` は `ref_lead_sep`/`ref_gt_lead`/`refs_comment_lead` 及び D1991–D2006)。
### Security — D2009: `References:`/`In-Reply-To:` の値頭の `` ` `` を検出 — `Envelope` に `refs_backtick_lead` を追加 (同上)。
### Security — D2008: `References:`/`In-Reply-To:` の値頭の `_` を検出 — `Envelope` に `refs_uscore_lead` を追加 (同上)。
### Security — D2007: `References:`/`In-Reply-To:` の値頭の `^` を検出 — `Envelope` に `refs_caret_lead` を追加 (同上)。
### Security — D2006: `References:`/`In-Reply-To:` の値頭の `]` を検出 — `Envelope` に `refs_rbrack_lead` を追加 (値頭の `;`/`,`/`>`/`(`/`"`/`!`/`=`/`:`/`*`/`#`/`$`/`@`/`?`/`&`/`'`/`+`/`/` は `ref_lead_sep`/`ref_gt_lead`/`refs_comment_lead` 及び D1991–D2002)。
### Security — D2005: `References:`/`In-Reply-To:` の値頭の `[` を検出 — `Envelope` に `refs_lbrack_lead` を追加 (同上)。
### Security — D2004: `References:`/`In-Reply-To:` の値頭の `-` を検出 — `Envelope` に `refs_minus_lead` を追加 (同上)。
### Security — D2003: `References:`/`In-Reply-To:` の値頭の `%` を検出 — `Envelope` に `refs_pct_lead` を追加 (同上)。
### Security — D2002: `References:`/`In-Reply-To:` の値頭の `/` を検出 — `Envelope` に `refs_slash_lead` を追加 (値頭の `;`/`,`/`>`/`(`/`"`/`!`/`=`/`:`/`*`/`#`/`$`/`@`/`?` は `ref_lead_sep`/`ref_gt_lead`/`refs_comment_lead` 及び D1991–D1998)。
### Security — D2001: `References:`/`In-Reply-To:` の値頭の `+` を検出 — `Envelope` に `refs_plus_lead` を追加 (同上)。
### Security — D2000: `References:`/`In-Reply-To:` の値頭の `'` を検出 — `Envelope` に `refs_apos_lead` を追加 (同上)。
### Security — D1999: `References:`/`In-Reply-To:` の値頭の `&` を検出 — `Envelope` に `refs_amp_lead` を追加 (同上)。
### Security — D1998: `References:`/`In-Reply-To:` の値頭の `?` を検出 — `Envelope` に `refs_qmark_lead` を追加 (値頭の `;`/`,`/`>`/`(`/`"`/`!`/`=`/`:`/`*` は D1931 前後の `ref_lead_sep`/`ref_gt_lead`/`refs_comment_lead` 及び D1991–D1994)。
### Security — D1997: `References:`/`In-Reply-To:` の値頭の `@` を検出 — `Envelope` に `refs_at_lead` を追加 (同上)。
### Security — D1996: `References:`/`In-Reply-To:` の値頭の `$` を検出 — `Envelope` に `refs_dollar_lead` を追加 (同上)。
### Security — D1995: `References:`/`In-Reply-To:` の値頭の `#` を検出 — `Envelope` に `refs_hash_lead` を追加 (同上)。
### Security — D1994: `References:`/`In-Reply-To:` の値頭の `*` を検出 — `Envelope` に `refs_star_lead` を追加 (値頭の `;`/`,` は `ref_lead_sep`、`>` は `ref_gt_lead`、`(` は `refs_comment_lead`)。
### Security — D1993: `References:`/`In-Reply-To:` の値頭の `:` を検出 — `Envelope` に `refs_colon_lead` を追加 (値頭の `;`/`,` は `ref_lead_sep`、`>` は `ref_gt_lead`、`(` は `refs_comment_lead`)。
### Security — D1992: `References:`/`In-Reply-To:` の値頭の `=` を検出 — `Envelope` に `refs_eq_lead` を追加 (値頭の `;`/`,` は `ref_lead_sep`、`>` は `ref_gt_lead`、`(` は `refs_comment_lead`)。
### Security — D1991: `References:`/`In-Reply-To:` の値頭の `!` を検出 — `Envelope` に `refs_bang_lead` を追加 (値頭の `;`/`,` は `ref_lead_sep`、`>` は `ref_gt_lead`、`(` は `refs_comment_lead`)。
### Security — D1990: `References:`/`In-Reply-To:` が `(` 始まりで識別子がコメント内になる異形を検出 — `Envelope` に `refs_comment_lead` を追加 (値頭の `;`/`,` は `ref_lead_sep`、`>` は `ref_gt_lead`)。
### Security — D1989: `Received:` の `by` 節の `}` を検出 — `Envelope` に `received_by_rbrace` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"`/`*`/`+`/`[`/`]`/`{` は D1845–D1988)。
### Security — D1988: `Received:` の `by` 節の `{` を検出 — `Envelope` に `received_by_lbrace` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"`/`*`/`+`/`[`/`]` は D1845–D1981)。
### Security — D1987: `Received:` の `with` 節の `\` を検出 — `Envelope` に `received_with_bslash` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*`/`+`/`{`/`}`/`[`/`]` は D1825–D1986)。
### Security — D1986: `Received:` の `with` 節の `]` を検出 — `Envelope` に `received_with_rbracket` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*`/`+`/`{`/`}`/`[` は D1825–D1985)。
### Security — D1985: `Received:` の `with` 節の `[` を検出 — `Envelope` に `received_with_lbracket` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*`/`+`/`{`/`}` は D1825–D1980)。
### Security — D1984: `Received:` の `via` 節の `}` を検出 — `Envelope` に `received_via_rbrace` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\`/`[`/`]`/`*`/`+`/`{` は D1766–D1983)。
### Security — D1983: `Received:` の `via` 節の `{` を検出 — `Envelope` に `received_via_lbrace` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\`/`[`/`]`/`*`/`+` は D1766–D1982)。
### Security — D1982: `Received:` の `via` 節の `+` を検出 — `Envelope` に `received_via_plus` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\`/`[`/`]`/`*` は D1766–D1978)。
### Security — D1981: `Received:` の `by` 節の `]` を検出 — `Envelope` に `received_by_rbracket` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"`/`*`/`+`/`[` は D1845–D1977)。
### Security — D1980: `Received:` の `with` 節の `}` を検出 — `Envelope` に `received_with_rbrace` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*`/`+`/`{` は D1825–D1976)。
### Security — D1979: `Received:` の `from` 節の `\` を検出 — `Envelope` に `received_from_bslash` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#`/`"`/`&`/`^`/`:`/`/` は D1837–D1975)。
### Security — D1978: `Received:` の `via` 節の `*` を検出 — `Envelope` に `received_via_star` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\`/`[`/`]` は D1766–D1974)。
### Security — D1977: `Received:` の `by` 節の `[` を検出 — `Envelope` に `received_by_lbracket` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"`/`*`/`+` は D1845–D1973)。
### Security — D1976: `Received:` の `with` 節の `{` を検出 — `Envelope` に `received_with_lbrace` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*`/`+` は D1825–D1972)。
### Security — D1975: `Received:` の `from` 節の `/` を検出 — `Envelope` に `received_from_slash` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#`/`"`/`&`/`^`/`:` は D1837–D1971)。
### Security — D1974: `Received:` の `via` 節の `]` を検出 — `Envelope` に `received_via_rbracket` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\`/`[` は D1766–D1970)。
### Security — D1973: `Received:` の `by` 節の `+` を検出 — `Envelope` に `received_by_plus` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"`/`*` は D1845–D1969)。
### Security — D1972: `Received:` の `with` 節の `+` を検出 — `Envelope` に `received_with_plus` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'`/`*` は D1825–D1968)。
### Security — D1971: `Received:` の `from` 節の `:` を検出 — `Envelope` に `received_from_colon` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#`/`"`/`&`/`^` は D1837–D1967)。
### Security — D1970: `Received:` の `via` 節の `[` を検出 — `Envelope` に `received_via_lbracket` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/`/`\` は D1766–D1964)。
### Security — D1969: `Received:` の `by` 節の `*` を検出 — `Envelope` に `received_by_star` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'`/`"` は D1845–D1966)。
### Security — D1968: `Received:` の `with` 節の `*` を検出 — `Envelope` に `received_with_star` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#`/`'` は D1825–D1961)。
### Security — D1967: `Received:` の `from` 節の `^` を検出 — `Envelope` に `received_from_caret` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#`/`"`/`&` は D1837–D1965)。
### Security — D1966: `Received:` の `by` 節の `"` を検出 — `Envelope` に `received_by_quote` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~`/`'` は D1845–D1962)。
### Security — D1965: `Received:` の `from` 節の `&` を検出 — `Envelope` に `received_from_amp` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#`/`"` は D1837–D1963)。
### Security — D1964: `Received:` の `via` 節の `\` を検出 — `Envelope` に `received_via_bslash` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|`/`/` は D1766–D1960)。
### Security — D1963: `Received:` の `from` 節の `"` を検出 — `Envelope` に `received_from_quote` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'`/`#` は D1837–D1959)。
### Security — D1962: `Received:` の `by` 節の `'` を検出 — `Envelope` に `received_by_apos` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:`/`\`/`~` は D1845–D1958)。
### Security — D1961: `Received:` の `with` 節の `'` を検出 — `Envelope` に `received_with_apos` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^`/`#` は D1825–D1957)。
### Security — D1960: `Received:` の `via` 節の `/` を検出 — `Envelope` に `received_via_slash` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^`/`|` は D1766–D1956)。
### Security — D1959: `Received:` の `from` 節の `#` を検出 — `Envelope` に `received_from_hash` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|`/`'` は D1837–D1930)。
### Security — D1958: `Received:` の `by` 節の `~` を検出 — `Envelope` に `received_by_tilde` を追加 (`by` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`|`/`&`/`$`/`?`/`,`/`:` は D1845–D1950)。
### Security — D1957: `Received:` の `with` 節の `#` を検出 — `Envelope` に `received_with_hash` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$`/`^` は D1825–D1953)。
### Security — D1956: `Received:` の `via` 節の `|` を検出 — `Envelope` に `received_via_pipe` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"`/`^` は D1766–D1952)。
### Security — D1955: `Received:` の `id` 節の `&` を検出 — `Envelope` に `received_id_amp` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~`/`$`/`'`/`?`/`,`/`:` は D1785–D1951)。
### Security — D1954: `Received:` の `for` 節の `|` を検出 — `Envelope` に `received_for_pipe` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&`/`#`/`"`/`'`/`:`/`,` は D1804–D1950)。
### Security — D1953: `Received:` の `with` 節の `^` を検出 — `Envelope` に `received_with_caret` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|`/`$` は D1825–D1949)。
### Security — D1952: `Received:` の `via` 節の `^` を検出 — `Envelope` に `received_via_caret` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,`/`"` は D1766–D1948)。
### Security — D1951: `Received:` の `id` 節の `:` を検出 — `Envelope` に `received_id_colon` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~`/`$`/`'`/`?`/`,` は D1785–D1947)。
### Security — D1950: `Received:` の `for` 節の `,` を検出 — `Envelope` に `received_for_comma` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&`/`#`/`"`/`'`/`:` は D1804–D1946)。
### Security — D1949: `Received:` の `with` 節の `$` を検出 — `Envelope` に `received_with_dollar` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~`/`|` は D1825–D1945)。
### Security — D1948: `Received:` の `via` 節の `"` を検出 — `Envelope` に `received_via_quote` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:`/`,` は D1766–D1944)。
### Security — D1947: `Received:` の `id` 節の `,` を検出 — `Envelope` に `received_id_comma` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~`/`$`/`'`/`?` は D1785–D1943)。
### Security — D1946: `Received:` の `for` 節の `:` を検出 — `Envelope` に `received_for_colon` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&`/`#`/`"`/`'` は D1804–D1942)。
### Security — D1945: `Received:` の `with` 節の `|` を検出 — `Envelope` に `received_with_pipe` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"`/`~` は D1825–D1941)。
### Security — D1944: `Received:` の `via` 節の `,` を検出 — `Envelope` に `received_via_comma` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?`/`:` は D1766–D1940)。
### Security — D1943: `Received:` の `id` 節の `?` を検出 — `Envelope` に `received_id_qmark` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~`/`$`/`'` は D1785–D1939)。
### Security — D1942: `Received:` の `for` 節の `'` を検出 — `Envelope` に `received_for_apos` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&`/`#`/`"` は D1804–D1936)。
### Security — D1941: `Received:` の `with` 節の `~` を検出 — `Envelope` に `received_with_tilde` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,`/`"` は D1825–D1938)。
### Security — D1940: `Received:` の `via` 節の `:` を検出 — `Envelope` に `received_via_colon` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&`/`?` は D1766–D1937)。
### Security — D1939: `Received:` の `id` 節の `'` を検出 — `Envelope` に `received_id_apos` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~`/`$` は D1785–D1933)。
### Security — D1938: `Received:` の `with` 節の `"` を検出 — `Envelope` に `received_with_quote` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?`/`,` は D1825–D1932)。
### Security — D1937: `Received:` の `via` 節の `?` を検出 — `Envelope` に `received_via_qmark` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$`/`&` は D1766–D1925)。
### Security — D1936: `Received:` の `for` 節の `"` を検出 — `Envelope` に `received_for_quote` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&`/`#` は D1804–D1931)。
### Security — D1935: `Received:` の `by` 節の `:` を検出 — `Envelope` に `received_by_colon` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\`/`|`/`&`/`$`/`?`/`,` は D1773–D1934)。
### Security — D1934: `Received:` の `by` 節の `,` を検出 — `Envelope` に `received_by_comma` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\`/`|`/`&`/`$`/`?` は D1773–D1924)。
### Security — D1933: `Received:` の `id` 節の `$` を検出 — `Envelope` に `received_id_dollar` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^`/`~` は D1785–D1928)。
### Security — D1932: `Received:` の `with` 節の `,` を検出 — `Envelope` に `received_with_comma` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&`/`?` は D1825–D1927)。
### Security — D1931: `Received:` の `for` 節の `#` を検出 — `Envelope` に `received_for_hash` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$`/`&` は D1804–D1929)。
### Security — D1930: `Received:` の `from` 節の `'` を検出 — `Envelope` に `received_from_apos` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~`/`|` は D1781–D1923)。
### Security — D1929: `Received:` の `for` 節の `&` を検出 — `Envelope` に `received_for_amp` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^`/`$` は D1804–D1926)。
### Security — D1928: `Received:` の `id` 節の `~` を検出 — `Envelope` に `received_id_tilde` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|`/`^` は D1785–D1922)。
### Security — D1927: `Received:` の `with` 節の `?` を検出 — `Envelope` に `received_with_qmark` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:`/`&` は D1825–D1921)。
### Security — D1926: `Received:` の `for` 節の `$` を検出 — `Envelope` に `received_for_dollar` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~`/`^` は D1804–D1918)。
### Security — D1925: `Received:` の `via` 節の `&` を検出 — `Envelope` に `received_via_amp` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~`/`$` は D1766–D1917)。
### Security — D1924: `Received:` の `by` 節の `?` を検出 — `Envelope` に `received_by_qmark` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\`/`|`/`&`/`$` は D1773–D1920)。
### Security — D1923: `Received:` の `from` 節の `|` を検出 — `Envelope` に `received_from_pipe` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$`/`~` は D1781–D1919)。
### Security — D1922: `Received:` の `id` 節の `^` を検出 — `Envelope` に `received_id_caret` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#`/`|` は D1785–D1914)。
### Security — D1921: `Received:` の `with` 節の `&` を検出 — `Envelope` に `received_with_amp` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@`/`:` は D1825–D1905)。
### Security — D1920: `Received:` の `by` 節の `$` を検出 — `Envelope` に `received_by_dollar` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\`/`|`/`&` は D1773–D1916)。
### Security — D1919: `Received:` の `from` 節の `~` を検出 — `Envelope` に `received_from_tilde` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,`/`$` は D1781–D1915)。
### Security — D1918: `Received:` の `for` 節の `^` を検出 — `Envelope` に `received_for_caret` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/`/`~` は D1804–D1911)。
### Security — D1917: `Received:` の `via` 節の `$` を検出 — `Envelope` に `received_via_dollar` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'`/`~` は D1766–D1913)。
### Security — D1916: `Received:` の `by` 節の `&` を検出 — `Envelope` に `received_by_amp` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\`/`|` は D1773–D1912)。
### Security — D1915: `Received:` の `from` 節の `$` を検出 — `Envelope` に `received_from_dollar` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`,` は D1781–D1906)。
### Security — D1914: `Received:` の `id` 節の `|` を検出 — `Envelope` に `received_id_pipe` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"`/`#` は D1785–D1910)。
### Security — D1913: `Received:` の `via` 節の `~` を検出 — `Envelope` に `received_via_tilde` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#`/`'` は D1766–D1909)。
### Security — D1912: `Received:` の `by` 節の `|` を検出 — `Envelope` に `received_by_pipe` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#`/`\` は D1773–D1908)。
### Security — D1911: `Received:` の `for` 節の `~` を検出 — `Envelope` に `received_for_tilde` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?`/`/` は D1804–D1907)。
### Security — D1910: `Received:` の `id` 節の `#` を検出 — `Envelope` に `received_id_hash` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/`"` は D1785–D1902)。
### Security — D1909: `Received:` の `via` 節の `'` を検出 — `Envelope` に `received_via_apos` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@`/`#` は D1766–D1904)。
### Security — D1908: `Received:` の `by` 節の `\` を検出 — `Envelope` に `received_by_bslash` を追加 (`by` の `<`/`>`/`=`/`%`/`@`/`#` は D1773–D1901)。
### Security — D1907: `Received:` の `for` 節の `/` を検出 — `Envelope` に `received_for_slash` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@`/`?` は D1804–D1903)。
### Security — D1906: `Received:` の `from` 節の `,` を検出 — `Envelope` に `received_from_comma` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@`/`?` は D1781–D1900)。
### Security — D1905: `Received:` の `with` 節の `:` を検出 — `Envelope` に `received_with_colon` を追加 (`with` の `<`/`>`/`=`/`!`/`%`/`@` は D1825–D1898)。
### Security — D1904: `Received:` の `via` 節の `#` を検出 — `Envelope` に `received_via_hash` を追加 (`via` の `<`/`>`/`=`/`!`/`%`/`@` は D1766–D1893)。
### Security — D1903: `Received:` の `for` 節の `?` を検出 — `Envelope` に `received_for_qmark` を追加 (`for` の `<`/`>`/`=`/`!`/`%`/`@` は D1804–D1894)。
### Security — D1902: `Received:` の `id` 節の `"` を検出 — `Envelope` に `received_id_quote` を追加 (`id` の `<`/`>`/`=`/`!`/`%`/`@`/複数は D1785–D1897)。
### Security — D1901: `Received:` の `by` 節の `#` を検出 — `Envelope` に `received_by_hash` を追加 (`by` の `<`/`>`/`=`/`%`/`@` は D1773–D1890)。
### Security — D1900: `Received:` の `from` 節の `?` を検出 — `Envelope` に `received_from_qmark` を追加 (`from` の `<`/`>`/`=`/`!`/`%`/`@` は D1781–D1889)。
### Security — D1899: `;file<name=x` の param 名 `<` を検出 — `Envelope` に `param_lt_name` を追加 (`>` は D1895)。
### Security — D1898: `Received:` の `with` 節の `>` を検出 — `Envelope` に `received_with_gt` を追加 (`with` の `<` は D1881)。
### Security — D1897: `Received:` の `id` 節の `>` を検出 — `Envelope` に `received_id_gt` を追加 (`id` の `<` は D1873)。
### Security — D1896: `Content-Transfer-Encoding: base"64` の値内 `"` を検出 — `Envelope` に `cte_quote` を追加 (`'`/`$`/`#`/`*`/`{`/`}`/`[`/`]`/`|`/`^`/`~` は D1860–D1892)。
### Security — D1895: `;file>name=x` の param 名 `>` を検出 — `Envelope` に `param_gt_name` を追加 (`(`/`)` は D1887/D1891)。
### Security — D1894: `Received:` の `for` 節の `>` を検出 — `Envelope` に `received_for_gt` を追加 (`for` の `<` は D1885)。
### Security — D1893: `Received:` の `via` 節の `>` を検出 — `Envelope` に `received_via_gt` を追加 (`via` の `<` は D1869)。
### Security — D1892: `Content-Transfer-Encoding: base'64` の値内 `'` を検出 — `Envelope` に `cte_apos` を追加 (`$`/`#`/`*`/`{`/`}`/`[`/`]`/`|`/`^`/`~` は D1860–D1888)。
### Security — D1891: `;file)name=x` の param 名 `)` を検出 — `Envelope` に `param_rparen_name` を追加 (`(` は D1887)。
### Security — D1890: `Received:` の `by` 節の `>` を検出 — `Envelope` に `received_by_gt` を追加 (`by` の `<` は D1865)。
### Security — D1889: `Received:` の `from` 節の `>` を検出 — `Envelope` に `received_from_gt` を追加 (`from` の `<` は D1877)。
### Security — D1888: `Content-Transfer-Encoding: base$64` の値内 `$` を検出 — `Envelope` に `cte_dollar` を追加 (`#`/`*`/`{`/`}`/`[`/`]`/`|`/`^`/`~` は D1860–D1884)。
### Security — D1887: `;file(name=x` の param 名 `(` を検出 — `Envelope` に `param_lparen_name` を追加 (孤立 `(` は ct_paren/cd_paren D1605 と共発火)。
### Security — D1886: `;file+name=x` の param 名 `+` を検出 — `Envelope` に `param_plus_name` を追加 (`'`/`#` は D1883/D1879)。
### Security — D1885: `Received:` の `for` 節の `<` を検出 — `Envelope` に `received_for_lt` を追加 (`for` の `!`/`%`/`@`/`=`/複数は D1777–D1853)。
### Security — D1884: `Content-Transfer-Encoding: base#64` の値内 `#` を検出 — `Envelope` に `cte_hash` を追加 (`*`/`{`/`}`/`[`/`]`/`|`/`^`/`~` は D1860–D1880)。
### Security — D1883: `;file'name=x` の param 名 `'` を検出 — `Envelope` に `param_apos_name` を追加 (`#` は D1879)。
### Security — D1882: `Message-ID: _<a>` 等の `_` 先立ちを検出 — `Envelope` に `msgid_uscore_lead` を追加 (lead-sep 系は D1755–D1878)。
### Security — D1881: `Received:` の `with` 節の `<` を検出 — `Envelope` に `received_with_lt` を追加 (`with` の `%`/`!`/`@`/`=` は D1825–D1857)。
### Security — D1880: `Content-Transfer-Encoding: base*64` の値内 `*` を検出 — `Envelope` に `cte_star` を追加 (`{`/`}`/`[`/`]`/`|`/`^`/`~` は D1860–D1876)。
### Security — D1879: `;file#name=x` の param 名 `#` を検出 — `Envelope` に `param_hash_name` を追加 (`$`/`~`/`^`/`|`/`}` は D1875–D1859)。
### Security — D1878: `Message-ID: }<a>` 等の `}` 先立ちを検出 — `Envelope` に `msgid_rbrace_lead` を追加 (lead-sep 系は D1755–D1874)。
### Security — D1877: `Received:` の `from` 節の `<` を検出 — `Envelope` に `received_from_lt` を追加 (`from` の `!`/`%`/`@`/`=`/クオートは D1781–D1861)。
### Security — D1876: `Content-Transfer-Encoding: base~64` の値内 `~` を検出 — `Envelope` に `cte_tilde` を追加 (`{`/`}`/`[`/`]`/`|`/`^` は D1860–D1872)。
### Security — D1875: `;file$name=x` の param 名 `$` を検出 — `Envelope` に `param_dollar_name` を追加 (`~`/`^`/`|`/`}` は D1871–D1859)。
### Security — D1874: `Message-ID: {<a>` 等の `{` 先立ちを検出 — `Envelope` に `msgid_lbrace_lead` を追加 (lead-sep 系は D1755–D1870)。
### Security — D1873: `Received:` の `id` 節の `<` を検出 — `Envelope` に `received_id_lt` を追加 (`id` の `!`/`%`/`@`/`=`/複数は D1785–D1849)。
### Security — D1872: `Content-Transfer-Encoding: base^64` の値内 `^` を検出 — `Envelope` に `cte_caret` を追加 (`{`/`}`/`[`/`]`/`|` は D1860–D1868)。
### Security — D1871: `;file~name=x` の param 名 `~` を検出 — `Envelope` に `param_tilde_name` を追加 (`^`/`|`/`}` は D1867/D1863/D1859)。
### Security — D1870: `Message-ID: ]<a>` 等の `]` 先立ちを検出 — `Envelope` に `msgid_rbrack_lead` を追加 (lead-sep 系は D1755–D1866)。
### Security — D1869: `Received:` の `via` 節の `<` を検出 — `Envelope` に `received_via_lt` を追加 (`via` の `!`/`@`/`=`/`%` は D1709系–D1841)。
### Security — D1868: `Content-Transfer-Encoding: base|64` の値内 `|` を検出 — `Envelope` に `cte_pipe` を追加 (`{`/`}`/`[`/`]` は D1860–D1856)。
### Security — D1867: `;file^name=x` の param 名 `^` を検出 — `Envelope` に `param_caret_name` を追加 (`|`/`}` は D1863/D1859)。
### Security — D1866: `Message-ID: [<a>` 等の `[` 先立ちを検出 — `Envelope` に `msgid_lbrack_lead` を追加 (lead-sep 系は D1755–D1862)。
### Security — D1865: `Received:` の `by` 節の `<` を検出 — `Envelope` に `received_by_lt` を追加 (`by` の `!`/`%`/`@`/`=` は D1709系–D1845)。
### Security — D1864: `Content-Transfer-Encoding: base}64` の値内 `}` を検出 — `Envelope` に `cte_rbrace` を追加 (`{`/`[`/`]` は D1860/D1852/D1856)。
### Security — D1863: `;file|name=x` の param 名 `|` を検出 — `Envelope` に `param_pipe_name` を追加 (`}` は D1859)。
### Security — D1862: `Message-ID: -<a>` 等の `-` 先立ちを検出 — `Envelope` に `msgid_minus_lead` を追加 (lead-sep 系は D1755–D1858)。
### Security — D1861: `Received:` の `from` 節の `=` を検出 — `Envelope` に `received_from_eq` を追加 (`via`/`by`/`id`/`for`/`with` の `=` は D1841–D1857)。
### Security — D1860: `Content-Transfer-Encoding: base{64` の値内 `{` を検出 — `Envelope` に `cte_lbrace` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%`/`!`/`?`/`/`/`[`/`]` は D1756–D1856)。
### Security — D1859: `;file}name=x` の param 名 `}` を検出 — `Envelope` に `param_rbrace_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:`/`%`/`,`/`[`/`]`/`{` は D1713–D1855)。
### Security — D1858: `Message-ID: "<a>` 等の `"` 先立ちを検出 — `Envelope` に `msgid_dquote_lead` を追加 (lead-sep 系は D1755–D1854)。
### Security — D1857: `Received:` の `with` 節の `=` を検出 — `Envelope` に `received_with_eq` を追加 (`with` の `%`/`!`/`@` は D1825/D1833/D1837、`via`/`by`/`id`/`for` の `=` は D1841–D1853)。
### Security — D1856: `Content-Transfer-Encoding: base]64` の値内 `]` を検出 — `Envelope` に `cte_rbrack` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%`/`!`/`?`/`/`/`[` は D1756–D1852)。
### Security — D1855: `;file{name=x` の param 名 `{` を検出 — `Envelope` に `param_lbrace_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:`/`%`/`,`/`[`/`]` は D1713–D1851)。
### Security — D1854: `Message-ID: +<a>` 等の `+` 先立ちを検出 — `Envelope` に `msgid_plus_lead` を追加 (lead-sep 系は D1755–D1850)。
### Security — D1853: `Received:` の `for` 節の `=` を検出 — `Envelope` に `received_for_eq` を追加 (`for` の `!`/`%`/`@@` は D1821/D1804/D1777、`via`/`by`/`id` の `=` は D1841/D1845/D1849)。
### Security — D1852: `Content-Transfer-Encoding: base[64` の値内 `[` を検出 — `Envelope` に `cte_lbrack` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%`/`!`/`?`/`/` は D1756–D1848)。
### Security — D1851: `;file]name=x` の param 名 `]` を検出 — `Envelope` に `param_rbrack_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:`/`%`/`,`/`[` は D1713–D1847)。
### Security — D1850: `Message-ID: '<a>` 等の `'` 先立ちを検出 — `Envelope` に `msgid_squote_lead` を追加 (lead-sep 系は D1755–D1846)。
### Security — D1849: `Received:` の `id` 節の `=` を検出 — `Envelope` に `received_id_eq` を追加 (`id` の `!`/`%`/`@` は D1785/D1800/D1827)。
### Security — D1848: `Content-Transfer-Encoding: base/64` の値内 `/` を検出 — `Envelope` に `cte_slash` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%`/`!`/`?` は D1756–D1844)。
### Security — D1847: `;file[name=x` の param 名 `[` を検出 — `Envelope` に `param_lbrack_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:`/`%`/`,` は D1713–D1843)。
### Security — D1846: `Message-ID: (<a>` 等の `(` 先立ち (識別子がコメント内) を検出 — `Envelope` に `msgid_lparen_lead` を追加 (lead-sep 系は D1755–D1842、合法 `(note)<a>` は不発火)。
### Security — D1845: `Received:` の `by` 節の `=` を検出 — `Envelope` に `received_by_eq` を追加 (`by` の `!`/`%`/`@` は D1813/D1793/D1773、`via` の `=` は D1841)。
### Security — D1844: `Content-Transfer-Encoding: base?64` の値内 `?` を検出 — `Envelope` に `cte_qmark` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%`/`!` は D1756–D1840)。
### Security — D1843: `;file,name=x` の param 名 `,` を検出 — `Envelope` に `param_comma_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:`/`%` は D1713–D1839)。
### Security — D1842: `Message-ID: )<a>` 等の `)` 先立ちを検出 — `Envelope` に `msgid_rparen_lead` を追加 (lead-sep 系は D1755–D1838)。
### Security — D1841: `Received:` の `via` 節の `=` を検出 — `Envelope` に `received_via_eq` を追加 (`via` の `!`/`@` は D1817/D1789)。
### Security — D1840: `Content-Transfer-Encoding: base!64` の値内 `!` を検出 — `Envelope` に `cte_bang` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`%` は D1756–D1836)。
### Security — D1839: `;file%name=x` の param 名 `%` を検出 — `Envelope` に `param_pct_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&`/`:` は D1713–D1835)。
### Security — D1838: `Message-ID: $<a>` 等の `$` 先立ちを検出 — `Envelope` に `msgid_dollar_lead` を追加 (lead-sep 系は D1755–D1834)。
### Security — D1837: `Received:` の `with` 節の `@` を検出 — `Envelope` に `received_with_at` を追加 (`with` の `%`/`!` は D1825/D1833)。
### Security — D1836: `Content-Transfer-Encoding: base%64` の値内 `%` を検出 — `Envelope` に `cte_pct` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@` は D1756–D1832)。
### Security — D1835: `;file:name=x` の param 名 `:` を検出 — `Envelope` に `param_colon_name` を追加 (`@`/`/`/`` ` ``/`?`/`!`/`&` は D1713–D1831)。
### Security — D1834: `Message-ID: ^<a>` 等の `^` 先立ちを検出 — `Envelope` に `msgid_caret_lead` を追加 (lead-sep 系は D1755–D1830)。
### Security — D1833: `Received:` の `with` 節の `!` を検出 — `Envelope` に `received_with_bang` を追加 (`with` の `%` は D1825)。
### Security — D1832: `Content-Transfer-Encoding: base@64` の値内 `@` を検出 — `Envelope` に `cte_at` を追加 (`=`/`:`/括弧/`\`/`>`/`<` は D1756–D1805)。
### Security — D1831: `;file&name=x` の param 名 `&` を検出 — `Envelope` に `param_amp_name` を追加 (`@`/`/`/`` ` ``/`?`/`!` は D1713–D1828)。
### Security — D1830: `Message-ID: `<a>` 等の反転符先立ちを検出 — `Envelope` に `msgid_backtick_lead` を追加 (lead-sep 系は D1755–D1826)。
### Security — D1829: `Content-Disposition: attach@ment` の型本体内 `@` を検出 — `Envelope` に `cd_at_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<` は D1759–D1801、CT 側は D1808)。
### Security — D1828: `;file!name=x` の param 名 `!` を検出 — `Envelope` に `param_bang_name` を追加 (`@`/`/`/`` ` ``/`?` は D1713/D1716/D1782/D1810)。
### Security — D1827: `Received:` の `id` 節の `@` を検出 — `Envelope` に `received_id_at` を追加 (`id` の `!`/`%` は D1785/D1800)。
### Security — D1826: `Message-ID: |<a>` 等の `|` 先立ちを検出 — `Envelope` に `msgid_pipe_lead` を追加 (lead-sep 系は D1755–D1822)。
### Security — D1825: `Received:` の `with` 節の `%` を検出 — `Envelope` に `received_with_pct` を追加 (`by`/`via`/`for` の `%`/`!` は D1793/D1809/D1804/D1817/D1821)。
### Security — D1824: `Content-Type: text]plain` の型本体内 `]` を検出 — `Envelope` に `ct_rbracket_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`?`/`,`/`[` は D1758–D1820)。
### Security — D1823: `To: a'b@c` のローカル部 `'` を検出 — `Envelope` に `addr_apos_local` を追加 (`*` D1819、`#` D1815、`%` D1811、`$` D1806、`|` D1802、`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1822: `Message-ID: ~<a>` 等の `~` 先立ちを検出 — `Envelope` に `msgid_tilde_lead` を追加 (lead-sep 系は D1755–D1818)。
### Security — D1821: `Received:` の `for` 節の `!` を検出 — `Envelope` に `received_for_bang` を追加 (`from`/`by`/`id`/`via` の `!` は D1781/D1813/D1785/D1817)。
### Security — D1820: `Content-Type: text[plain` の型本体内 `[` を検出 — `Envelope` に `ct_lbracket_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`?`/`,` は D1758–D1816)。
### Security — D1819: `To: a*b@c` のローカル部 `*` を検出 — `Envelope` に `addr_star_local` を追加 (`#` D1815、`%` D1811、`$` D1806、`|` D1802、`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1818: `Message-ID: &<a>` 等の `&` 先立ちを検出 — `Envelope` に `msgid_amp_lead` を追加 (lead-sep 系は D1755–D1814)。
### Security — D1817: `Received:` の `via` 節の `!` を検出 — `Envelope` に `received_via_bang` を追加 (`by` の `!` は D1813、`via` の `@`/`%` は D1789/D1809)。
### Security — D1816: `Content-Type: text,plain` の型本体内 `,` を検出 — `Envelope` に `ct_comma_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@`/`?` は D1758–D1812)。
### Security — D1815: `To: a#b@c` のローカル部 `#` を検出 — `Envelope` に `addr_hash_local` を追加 (`%` D1811、`$` D1806、`|` D1802、`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1814: `Message-ID: #<a>` 等の `#` 先立ちを検出 — `Envelope` に `msgid_hash_lead` を追加 (lead-sep 系は D1755–D1807)。
### Security — D1813: `Received:` の `by` 節の `!` を検出 — `Envelope` に `received_by_bang` を追加 (`from`/`id` の `!` は D1781/D1785、`by` の `@`/`%` は D1773/D1793)。
### Security — D1812: `Content-Type: text?plain` の型本体内 `?` を検出 — `Envelope` に `ct_qmark_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<`/`@` は D1758–D1808)。
### Security — D1811: `To: a%b@c` のローカル部 `%` を検出 — `Envelope` に `addr_pct_local` を追加 (UUCP 旧式パーセント経路。`$` D1806、`|` D1802、`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1810: `;file?name=x` の param 名 `?` を検出 — `Envelope` に `param_qmark_name` を追加 (`@` は D1713、`/` は D1716、反転符は D1782)。
### Security — D1809: `Received:` の `via` 節の `%` を検出 — `Envelope` に `received_via_pct` を追加 (`via` の `@` は D1789、`from`/`by`/`id`/`for` の `%` は D1797/D1793/D1800/D1804)。
### Security — D1808: `Content-Type: text@plain` の型本体内 `@` を検出 — `Envelope` に `ct_at_type` を追加 (`=`/`:`/括弧/`\`/`>`/`<` は D1758–D1796)。
### Security — D1807: `Message-ID: /<a>` 等の `/` 先立ちを検出 — `Envelope` に `msgid_slash_lead` を追加 (lead-sep 系は D1755–D1803)。
### Security — D1806: `To: a$b@c` のローカル部 `$` を検出 — `Envelope` に `addr_dollar_local` を追加 (`|` D1802、`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1805: `Content-Transfer-Encoding: base<64` の値内 `<` を検出 — `Envelope` に `cte_lt` を追加 (`>` は D1798、`=` は D1780、`\` は D1788)。
### Security — D1804: `Received:` の `for` 節の `%` を検出 — `Envelope` に `received_for_pct` を追加 (`for` の `@` 二つは D1777、`id`/`by`/`from` の `%` は D1800/D1793/D1797)。
### Security — D1803: `Message-ID: !<a>` 等の `!` 先立ちを検出 — `Envelope` に `msgid_bang_lead` を追加 (lead-sep 系は D1755–D1799)。
### Security — D1802: `To: a|b@c` のローカル部 `|` を検出 — `Envelope` に `addr_pipe_local` を追加 (`&` D1760、`~` D1763、`{}` D1767、`^` D1770、`` ` `` D1771 と同族)。
### Security — D1801: `Content-Disposition: attach<ment` の型本体内 `<` を検出 — `Envelope` に `cd_lt_type` を追加 (`>` は D1794、`:` は D1765、`\` は D1786)。
### Security — D1800: `Received:` の `id` 節の `%` を検出 — `Envelope` に `received_id_pct` を追加 (`id` の `!` は D1785、`by`/`from` の `%` は D1793/D1797)。
### Security — D1799: `Message-ID: @<a>` 等の `@` 先立ちを検出 — `Envelope` に `msgid_at_lead` を追加 (lead-sep 系は D1755–D1795)。
### Security — D1798: `Content-Transfer-Encoding: base>64` の値内 `>` を検出 — `Envelope` に `cte_gt` を追加 (`=` は D1780、`\` は D1788、`,` は D1734)。
### Security — D1797: `Received:` の `from` 節の `%` を検出 — `Envelope` に `received_from_pct` を追加 (`by` の `%` は D1793、`from` の `!` は D1781、`@` は D1710)。
### Security — D1796: `Content-Type: text<plain` の型本体内 `<` を検出 — `Envelope` に `ct_lt_type` を追加 (`>` は D1792、`:` は D1761、`\` は D1784)。
### Security — D1795: `Message-ID: ?<a>` 等の `?` 先立ちを検出 — `Envelope` に `msgid_qmark_lead` を追加 (lead-sep 系は D1755–D1791)。
### Security — D1794: `Content-Disposition: attach>ment` の型本体内 `>` を検出 — `Envelope` に `cd_gt_type` を追加 (`:` は D1765、`=` は D1759、`\` は D1786)。
### Security — D1793: `Received:` の `by` 節の `%` を検出 — `Envelope` に `received_by_pct` を追加 (`by` の `@` は D1773、`from` の `!` は D1781)。
### Security — D1792: `Content-Type: text>plain` の型本体内 `>` を検出 — `Envelope` に `ct_gt_type` を追加 (`:` は D1761、`=` は D1758、`\` は D1784)。
### Security — D1791: `Message-ID: ><a>` 等の `>` 先立ちを検出 — `Envelope` に `msgid_gt_lead` を追加 (References 側は D1757、`<<` は D1787)。
### Security — D1790: `<a\b@c>` 等、msgid 系額縁内の逆斜線を検出 — `Envelope` に `msgid_inner_bslash` を追加 (額縁内空白は D1772、宛名の `\` は local_backslash)。
### Security — D1789: `Received:` の `via` 節の `@` を検出 — `Envelope` に `received_via_at` を追加 (`by` 節の `@` は D1773、`for` 節の `@` 二つは D1777)。
### Security — D1788: `Content-Transfer-Encoding: base\64` の値内逆斜線を検出 — `Envelope` に `cte_bslash` を追加 (`=` は D1780、`;` 先立ちは D1756、`,` は D1734)。
### Security — D1787: `Message-ID: <<a>` 等の二重 `<` 先立ちを検出 — `Envelope` に `msgid_lt_lead` を追加 (`;`/`,`/`=`/`%`/`:` 先立ちは D1755–D1783)。
### Security — D1786: `Content-Disposition: attach\ment` の型本体内逆斜線を検出 — `Envelope` に `cd_bslash_type` を追加 (`:` は D1765、`=` は D1759、孤立括弧は D1766)。
### Security — D1785: `Received:` の `id` 節の `!` を検出 — `Envelope` に `received_id_bang` を追加 (`from` 節の `!` は D1781、id 節重複は D1715)。
### Security — D1784: `Content-Type: text\plain` の型本体内逆斜線を検出 — `Envelope` に `ct_bslash_type` を追加 (`:` は D1761、`=` は D1758、孤立括弧は D1764)。
### Security — D1783: `Message-ID: :<a>` 等の `:` 先立ちを検出 — `Envelope` に `msgid_colon_lead` を追加 (`;` は D1755、`,` は D1769、`=` は D1774、`%` は D1779)。
### Security — D1782: `;file`name=x` の param 名の反転符を検出 — `Envelope` に `param_backtick_name` を追加 (`@` は D1713、`/` は D1716、`*` 先頭は D1735)。
### Security — D1781: `Received:` の `from` 節の `!` を検出 — `Envelope` に `received_from_bang` を追加 (from 節の `@` は D1710、for 節の `@` 二つは D1777)。
### Security — D1780: `Content-Transfer-Encoding: base=64` の値内 `=` を検出 — `Envelope` に `cte_eq` を追加 (`;` 先立ちは D1756、`,` は D1734、孤立括弧は D1768)。
### Security — D1779: `Message-ID: %<a>` 等の `%` 先立ちを検出 — `Envelope` に `msgid_pct_lead` を追加 (`;` は D1755、`,` は D1769、`=` は D1774)。
### Security — D1778: `To: : a@b;` の無名グループを検出 — `Envelope` に `addr_noname_group` を追加 (`:` だけは D1750、`label:;` 空要素は empty_group_syntax)。
### Security — D1777: `Received:` の `for` 節の `@` 二つを検出 — `Envelope` に `received_for_two_at` を追加 (`by` 節の `@` は D1773)。
### Security — D1776: `Content-Disposition: *` のワイルドカード型を検出 — `Envelope` に `cd_star_type` を追加。
### Security — D1775: `boundary="a;b"` クオート境界値内の `;` を検出 — `Envelope` に `boundary_quoted_semi` を追加 (非クオートは boundary_semicolon)。
### Security — D1774: `Message-ID:`/`List-Id:`/`Content-ID:` 系の `=` 先立ちを検出 — `Envelope` に `msgid_eq_lead` を追加 (`;` は D1755、`,` は D1769)。
### Security — D1773: `Received:` の `by` 節の `@` `by user@host` を検出 — `Envelope` に `received_by_at` を追加 (`from` 節の `@` は D1710)。
### Security — D1772: `List-Id:`/`Content-ID:` を含む msgid 系の額縁内空白 `<a b@l>` を検出 — `Envelope` に `msgid_ws_inner` を追加 (`spaced_msgid` D1516 の上位互換 — 4欄→6欄)。
### Security — D1771: 宛名ローカル部の `` ` `` ``a`b@c`` を検出 — `Envelope` に `addr_backtick_local` を追加 (`^`/`{}`/`&`/`~` は D1770/D1767/D1760/D1763)。
### Security — D1770: 宛名ローカル部の `^` `a^b@c` を検出 — `Envelope` に `addr_caret_local` を追加 (`{}` は D1767、`&`/`~` は D1760/D1763)。
### Security — D1769: `Message-ID:`/`List-Id:`/`Content-ID:` 系の `,` 先立ちを検出 — `Envelope` に `msgid_comma_lead` を追加 (`;` 先立ちは D1755、References 系は D1751)。
### Security — D1768: `Content-Transfer-Encoding:` 値本体内の孤立括弧 `base64(x`/`7bit)` を検出 — `Envelope` に `cte_paren` を追加 (CT 側は D1764、CD 側は D1766)。
### Security — D1767: 宛名ローカル部の `{`/`}` `a{b@c`/`a}b@c` を検出 — `Envelope` に `addr_brace_local` を追加 (表示名とクオート内は除外)。
### Security — D1766: `Content-Disposition:` 型本体内の孤立括弧 `attachment(x`/`attachment)` を検出 — `Envelope` に `cd_paren` を追加 (型二語案は既存 `spaced_media_type` D1512 と重複判明のため差替、CT 側は D1764)。あわせて `spaced_media_type` が合法コメント `text/plain (note)` で誤発火する件を修正。
### Security — D1765: `Content-Disposition:` 型本体内の `:` `attachment:x` を検出 — `Envelope` に `cd_colon_type` を追加 (CT 側は D1761、`=` は D1759)。
### Security — D1764: `Content-Type:` 型本体内の孤立括弧 `text(plain` を検出 — `Envelope` に `ct_paren` を追加 (合法コメント `(…)` は除外)。
### Security — D1763: 宛名ローカル部の `~` `a~b@c` を検出 — `Envelope` に `addr_tilde_local` を追加 (`&` は D1760、その他特殊字は D1557)。
### Security — D1762: 宛名欄の同一アドレス重複 `To: a@b, a@b` を検出 — `Envelope` に `same_addr_dup` を追加 (同名欄の重複は D1605 系、識別子重複は D1742)。
### Security — D1761: `Content-Type:` 型本体内の `:` `text:plain` を検出 — `Envelope` に `ct_colon_type` を追加 (`=` は D1758)。
### Security — D1760: 宛名ローカル部の `&` `a&b@c` を検出 — `Envelope` に `addr_amp_local` を追加 (表示名の `&` とクオート内は除外)。
### Security — D1759: `Content-Disposition:` 型本体内の `=` `attachment=x` を検出 — `Envelope` に `cd_eq_type` を追加 (CT 側は D1758)。
### Security — D1758: `Content-Type:` 型本体内の `=` `text=plain` を検出 — `Envelope` に `ct_eq_type` を追加 (クオートドメイン案は既存 `msgid_quoted_local` と重複判明のため差替)。
### Security — D1757: `References:`/`In-Reply-To:` の `>` 先立ち `><a>` を検出 — `Envelope` に `ref_gt_lead` を追加 (宛名側は D1753、`<` 無し `>` は D1635)。
### Security — D1756: `CTE:` の `;` 先立ち `;base64` を検出 — `Envelope` に `cte_semi_lead` を追加 (Received の `;` 先立ちは D1743)。
### Security — D1755: `Message-ID:`/`List-Id:`/`Content-ID:` 系の `;` 先立ちを検出 — `Envelope` に `msgid_semi_lead` を追加 (References/In-Reply-To は D1751)。
### Security — D1754: msgid 系の `<@b>`/`<a@>` 側欠落を検出 — `Envelope` に `msgid_empty_side` を追加 (宛名側は D1560 系、`@` 無しは D1746)。
### Security — D1753: 宛名欄の `>` 先立ち `To: >a@b` を検出 — `Envelope` に `addr_gt_lead` を追加 (末尾孤立 `>` は D1685; `/plain` 案は既存 `edge_slash_ct` と重複判明のため差替)。
### Security — D1752: msgid 系の `<…>` 隣接コメント `(x)<a>`/`<a>(x)` を検出 — `Envelope` に `msgid_paren` を追加 (額の中のコメントは D1619、空白隔ては正規形で不発火)。
### Security — D1751: `References:`/`In-Reply-To:` の先頭 `;`/`,` を検出 — `Envelope` に `ref_lead_sep` を追加 (宛名の `;` のみは D1730)。
### Security — D1750: 宛名欄の `:` のみ値 `To: :` を検出 — `Envelope` に `addr_colon_only` を追加 (`;` のみは D1730、`,` のみは D1732)。
### Security — D1749: `boundary=` 裸値の内部空白 `boundary=a b` を検出 — `Envelope` に `boundary_inner_ws` を追加 (端点空白は D1658、端点ドットは D1740)。
### Security — D1748: `Content-Type:` の `//` 空セグメント `text//plain` を検出 — `Envelope` に `ct_double_slash` を追加 (`/` 無しは D1705、サブ型欠落は D1733)。
### Security — D1747: 宛名欄の `@` 二つ `a@b@c` を検出 — `Envelope` に `two_at_addr` を追加 (msgid 系の `@` 二つは D1722、クオート内の `@` は除外; `multi_at_addr` の上位互換で Return-Path/コメント位置も拾う)。
### Security — D1746: `Message-ID:` 系の `@` 無し識別子 `<abc>` を検出 — `Envelope` に `msgid_no_at` を追加 (`<>` 空は D1625)。
### Security — D1745: 宛名欄の `<…>` 二組 `From: <a> <b>`/`, ` 無し `To: <a> <b>` を検出 — `Envelope` に `addr_two_angle` を追加 (異名グループは D1738)。
### Security — D1744: `CTE:` 値の大文字 `BASE64` を検出 — `Envelope` に `cte_upper` を追加 (CT 型の大文字は D1613)。
### Security — D1743: `Received:` の `;` 先立ち `; date` を検出 — `Envelope` に `received_semi_lead` を追加 (`;` のみ値は D1690、日付節の空は D1737)。
### Security — D1742: `References:`/`In-Reply-To:` の同一識別子重複 `<a@x> <a@x>` を検出 — `Envelope` に `msgid_ref_dup` を追加 (異名二識別子は D1666)。
### Security — D1741: `Received:` 節値の `:` `from mx:25` を検出 — `Envelope` に `received_port` を追加 (節の空値・重複・欠落は D1691/D1707/D1720 系)。
### Security — D1740: `boundary=` 値の端点ドット `boundary=.abc`/`boundary=abc.` を検出 — `Envelope` に `boundary_dot_edge` を追加 (空白端点は D1658、英数字なしは D1718)。
### Security — D1739: `Message-ID:` 系のドメイン端点ドット `<a@.b>`/`<a@b.>` を検出 — `Envelope` に `msgid_edge_dot_domain` を追加 (宛名欄の先頭ドットは D1603 系)。
### Security — D1738: 宛名欄の二つの異名グループ `To: a: x@h; b: y@h;` を検出 — `Envelope` に `addr_two_groups` を追加 (同名グループ重複は D1667)。
### Security — D1737: `Received:` の `;` 後日付節欠落 `from a by b;` を検出 — `Envelope` に `received_date_empty` を追加 (`;` 自体の欠落は D1586、欄全体の空値は D1687)。
### Security — D1736: `Resent-*` 欄の規格外順序 (`Resent-To:` が `Resent-From:` より先) を検出 — `Envelope` に `resent_out_of_order` を追加 (同名重複は D1676)。(同名重複は既存 D1676 `dup_resent_headers` と重複判明のため差替)
### Security — D1735: param 名の `*` 先頭 `;*file=x` を検出 — `Envelope` に `param_star_name` を追加 (name*= の形崩れは D1614)。
### Security — D1734: `Content-Transfer-Encoding:` の `,` 区切り `base64,7bit` を検出 — `Envelope` に `cte_comma` を追加 (空白区切り二値は D1717)。
### Security — D1733: `Content-Type:` のサブ型欠落 `text/` を検出 — `Envelope` に `ct_empty_subtype` を追加 (`/` 無しは D1705、型本体欠落は D1649)。
### Security — D1732: 宛名欄の `,` のみ値 `To: ,` を検出 — `Envelope` に `addr_comma_only` を追加 (`;` のみは D1730、空値は D1681)。
### Security — D1731: `References:`/`In-Reply-To:` の識別子列の `;` `<a>;<b>` を検出 — `Envelope` に `msgid_ref_semicolon` を追加 (列の `,` は D1729)。
### Security — D1730: 宛名欄の `;` のみ値 `To: ;` を検出 — `Envelope` に `addr_semicolon_only` を追加 (空値は D1681)。
### Security — D1729: `References:`/`In-Reply-To:` の識別子列の `,` `<a>,<b>` を検出 — `Envelope` に `msgid_ref_comma` を追加 (識別子内 `%`/`!` は D1626)。
### Security — D1728: 同一欄内の同名 param 重複 `;charset=a; charset=b` を検出 — `Envelope` に `param_name_dup` を追加 (boundary 限定の重複は D1725)。(裸名札は既存 D1504 `has_bare_param` と重複判明のため差替)
### Security — D1727: `Received:` の `via` 節空値 `via;` を検出 — `Envelope` に `received_via_empty` を追加 (空 for 節は D1726)。
### Security — D1726: `Received:` の `for` 節空値 `for;` を検出 — `Envelope` に `received_for_empty` を追加 (for 節重複は D1712、空 id 節は D1724)。(クオート符丁は既存 D1474 と重複判明のため差替)
### Security — D1725: 同一欄内の `boundary=` 重複 `boundary=a; boundary=b` を検出 — `Envelope` に `boundary_param_dup` を追加 (欄またぎの大小写衝突は D1701)。
### Security — D1724: `Received:` の `id` 節空値 `id;` を検出 — `Envelope` に `received_id_empty` を追加 (id 節重複は D1715、空 by 節は D1720)。
### Security — D1723: `Received:` の `with` 節空値 `with;` を検出 — `Envelope` に `received_with_empty` を追加 (空 by 節は D1720)。
### Security — D1722: 識別子 `<…>` 内の `@` 2つ `<a@b@c>` を検出 — `Envelope` に `msgid_two_at` を追加 (識別子内 `:`/`\\` は `has_msgid_bad_char`)。
### Security — D1721: `Content-Disposition:` の型トークン2つ `attachment inline` を検出 — `Envelope` に `cd_two_types` を追加 (型欠落は D1708、CT 二重型は D1621)。
### Security — D1720: `Received:` の `by` 節空値 `from a by;` を検出 — `Envelope` に `received_by_empty` を追加 (空 from 節は D1703)。
### Security — D1719: `Received:` の `via` 節重複を検出 — `Envelope` に `received_multi_via` を追加 (id 節は D1715)。
### Security — D1718: 英数字を含まない `boundary=` 値を検出 — `Envelope` に `alnumless_boundary` を追加 (bchars 外は D1317、`-` 始まりは `has_dash_boundary`)。
### Security — D1717: `Content-Transfer-Encoding:` の値トークン2つを検出 — `Envelope` に `two_cte_values` を追加 (余分な空白は D1714、`;` 混入は D1655)。
### Security — D1716: param 名の `/` `;file/name=x` を検出 — `Envelope` に `slash_param_name` を追加 (名の `@` は D1713、値の `/` は D1704)。
### Security — D1715: `Received:` の `id` 節重複を検出 — `Envelope` に `received_multi_id` を追加 (with 節は D1711、for 節は D1712)。
### Security — D1714: `Content-Transfer-Encoding:` 値の余分な空白を検出 — `Envelope` に `padded_cte` を追加 (欄の `;` 混入は D1655)。
### Security — D1713: param 名の `@` `;file@name=x` を検出 — `Envelope` に `at_param_name` を追加 (名の空白は D1656、名なしは `has_empty_param_name`)。
### Security — D1712: `Received:` の `for` 節重複を検出 — `Envelope` に `received_multi_for` を追加。
### Security — D1711: `Received:` の `with` 節重複を検出 — `Envelope` に `received_multi_with` を追加 (`from` 節重複は D1688、`by` 節重複は D1707)。
### Security — D1710: `Received:` の `from` 節の裸 `@` `from user@host` を検出 — `Envelope` に `received_from_at` を追加 (from 節欠落は D1673、空 from 節は D1703)。
### Security — D1709: `Received:` の `from` 節クオート名 `from "mx"` を検出 — `Envelope` に `received_from_quoted` を追加。
### Security — D1708: `Content-Disposition: ; x=y` の型欠落を検出 — `Envelope` に `cd_empty_type` を追加 (型本体の空値は D1645、CT 型欠落は D1649)。
### Security — D1707: `Received:` の `by` 節重複を検出 — `Envelope` に `received_multi_by` を追加 (`from` 節重複は D1688)。
### Security — D1706: 識別子 `<a@localhost>` のドット無しドメインを検出 — `Envelope` に `msgid_dotless_domain` を追加 (宛名欄側は D1697)。
### Security — D1705: `Content-Type: text` のサブ型欠落を検出 — `Envelope` に `ct_no_subtype` を追加 (型本体の欠落は D1649、空値は D1645、二重 `/` は D1356)。
### Security — D1704: param 裸値の `/` `;charset=utf/8` を検出 — `Envelope` に `slash_param_value` を追加 (値内 `:` は D1659、第二 `=` は D1647)。
### Security — D1703: `Received:` の空 `from` 節を検出 — `Envelope` に `received_from_empty` を追加 (`from` 節欠落は D1673、`by` 節欠落は D1691)。
### Security — D1702: `List-Id:` の二識別子 `<a> <b>` を検出 — `Envelope` に `two_list_ids` を追加 (Message-ID 側は D1666)。
### Security — D1701: 大小写のみ異なる複数 `boundary=` 値を検出 — `Envelope` に `boundary_case_collide` を追加 (同一値再利用は D1669)。
### Security — D1700: param 引用値内の `=` `;charset="a=b"` を検出 — `Envelope` に `param_quoted_eq` を追加 (クオート内 `;` は D1609)。
### Security — D1699: Date 欄の5桁以上の年を検出 — `Envelope` に `year_5digit` を追加 (2桁年は D1535、二年は D1675)。
### Security — D1698: param の `=` 直前空白 `;key =v` を検出 — `Envelope` に `pre_eq_space` を追加 (`=` 直後の空白は D1651)。
### Security — D1697: 宛名のドット無し単ラベルドメイン `a@localhost` を検出 — `Envelope` に `single_label_domain` を追加 (ドメイン欠落は D1679)。
### Security — D1696: CT/CD param の空値 `;charset=` を検出 — `Envelope` に `param_empty_value` を追加 (名なしは `has_empty_param_name`、空節は D1636)。
### Security — D1695: Date 欄の数字曜日 `4,` を検出 — `Envelope` に `numeric_dow` を追加 (綴り違い曜日は D1582)。
### Security — D1694: `Received:` の `;` 複数を検出 — `Envelope` に `multi_semi_received` を追加 (`;` のみ値は D1690、`;` 欠落は D1586)。
### Security — D1693: CT/CD 欄の末尾 `;` を検出 — `Envelope` に `trailing_semi_param` を追加 (連続 `;;` は D1636)。
### Security — D1692: Date 欄の二つの月名を検出 — `Envelope` に `date_two_months` を追加 (二年は D1675、二つの日は D1689)。
### Security — D1691: `Received:` の `by` 節欠落を検出 — `Envelope` に `received_no_by` を追加 (from 欠落は D1673)。
### Security — D1690: `Received:` の `;` のみ値を検出 — `Envelope` に `received_semi_only` を追加 (空値は D1687、`;` 欠落は D1586)。
### Security — D1689: Date 欄の二つの日を検出 — `Envelope` に `date_two_days` を追加 (二年は D1675、二曜日は D1660、二時刻は D1657)。
### Security — D1688: `Received:` の `from` 節重複を検出 — `Envelope` に `received_multi_from` を追加 (from 欠落は D1673)。
### Security — D1687: `Received:` の空値を検出 — `Envelope` に `empty_received` を追加 (from 節欠落は D1673)。
### Security — D1686: Date 欄の数字+英字融合語 `25Sep2025` を検出 — `Envelope` に `fused_date` を追加。
### Security — D1685: 宛名欄の `<` 無し `>` を検出 — `Envelope` に `addr_gt_only` を追加 (message-id 側は D1635)。
### Security — D1684: Date 欄ゾーンの符号のみ `+`/`-` を検出 — `Envelope` に `zone_sign_only` を追加 (桁異常は D1670)。
### Security — D1683: Date 欄ゾーンの `+ABCD` 符号+英字形を検出 — `Envelope` に `zone_alpha` を追加 (裸英字は obs-zone 合法)。
### Security — D1682: 宣言なき `--boundary` 様の本文区切り行を検出 — `Envelope` に `orphan_boundary` を追加 (宣言済み孤児パートは `has_orphaned_part_content`)。
### Security — D1681: 宛名欄の空値を検出 — `Envelope` に `empty_addr_header` を追加 (空要素は D1584)。
### Security — D1680: `boundary=` の空白のみ値を検出 — `Envelope` に `ws_boundary` を追加 (空値は `has_empty_boundary`)。
### Security — D1679: 宛名欄の `@` 終端 (ドメイン欠落) を検出 — `Envelope` に `addr_at_end` を追加。
### Security — D1678: Date 欄の時刻のみ値を検出 — `Envelope` に `date_time_only` を追加 (時刻無しは D1610)。
### Security — D1677: Date 欄ゾーンの二重符号 `+-0900` を検出 — `Envelope` に `zone_two_signs` を追加。
### Security — D1676: `Resent-*` 欄の同名重複を検出 — `Envelope` に `dup_resent_headers` を追加 (通常欄重複は D1589/D1598)。
### Security — D1675: Date 欄の二つの4桁年を検出 — `Envelope` に `two_years` を追加 (年欠落は D1653、年先頭は D1664)。
### Security — D1674: Date 欄ゾーンの `+HH:MM` コロン形を検出 — `Envelope` に `zone_colon` を追加 (桁異常は D1670)。
### Security — D1673: `Received:` の `from` 節欠落を検出 — `Envelope` に `received_no_from` を追加 (欄異常は `has_bad_received`、`;` 欠落は D1586)。
### Security — D1669: 親子 multipart の同一 `boundary=` 値再利用を検出 — `Envelope` に `nested_boundary_reuse` を追加 (長さ上限は D1402)。

### Security — D1670: Date 欄ゾーンの `sign + 非4桁` (`+090`/`+9`) を検出 — `Envelope` に `bad_zone_len` を追加 (範囲外は D1565)。

### Security — D1671: Date 欄の `.` 区切り日付 (`25.09.2025`) を検出 — `Envelope` に `dot_date` を追加 (`-` は D1654、`/` は D1668)。

### Security — D1672: Date 欄の二数値ゾーン (`+0900 -0500`) を検出 — `Envelope` に `two_num_zones` を追加。

### Security — D1665: Date 欄の `AM`/`PM`/`a.m.`/`p.m.` 記号 (`12:00 PM`) を検出 — `Envelope` に `ampm_time` を追加。

### Security — D1666: `Message-ID:`/`Resent-Message-ID:` の二識別子を検出 — `Envelope` に `two_msgids` を追加 (References は複数正規)。

### Security — D1667: アドレス欄の重複グループ名 (`team: a@b; team: c@d;`) を検出 — `Envelope` に `addr_group_dup` を追加。

### Security — D1668: Date 欄の `/` 区切り日付 (`25/09/2025`) を検出 — `Envelope` に `slash_date` を追加 (`-` 区切りは D1654)。

### Security — D1661: `Message-ID:`/`Resent-Message-ID:` の `<>` 欠落を検出 — `Envelope` に `unbracketed_msgid` を追加 (裸参照は `bare_msgid_ref` が In-Reply-To/References のみ担当)。

### Security — D1662: Date 欄の符号なし4桁ゾーン (`12:00 0900`) を検出 — `Envelope` に `unsigned_zone` を追加。

### Security — D1663: param 値の閉じクオート後の続き文字 (`;x="a"b`) を検出 — `Envelope` に `quote_tail_param` を追加 (未終端クオートは D1600)。

### Security — D1664: Date 欄の年先頭並び (`2025 Sep 25`) を検出 — `Envelope` に `year_first_date` を追加 (月先頭は D1577)。

### Security — D1657: Date 欄の二時刻 (`12:00:00 14:30:00`) を検出 — `Envelope` に `date_two_times` を追加。

### Security — D1658: クオート boundary 値の端空白 (`" x"`/`"x "`) を検出 — `Envelope` に `boundary_edge_ws` を追加 (中央空白は bchars 正規)。

### Security — D1659: CT/CD 欄 param 裸値の `:` (`charset=x:y`) を検出 — `Envelope` に `colon_param_val` を追加。

### Security — D1660: Date 欄の二曜日名 (`Mon, Tue, …`) を検出 — `Envelope` に `two_daynames` を追加 (曜日不一致は D1569)。

### Security — D1653: Date 欄の年欠落 (`25 Sep`) を検出 — `Envelope` に `date_no_year` を追加 (2桁年は D1535)。

### Security — D1654: Date 欄の `-` 区切り日付 (`25-Sep-2025`) を検出 — `Envelope` に `dash_date` を追加。

### Security — D1655: `Content-Transfer-Encoding:` 値の `;` param を検出 — `Envelope` に `cte_param` を追加 (CTE は param を取らない)。

### Security — D1656: CT/CD 欄の param キーの非 token 文字 (`;a b=x`) を検出 — `Envelope` に `bad_param_key` を追加 (値側は D1647/D1515)。D1642 の doc に D1374 との併記関係を注記。

### Security — D1649: `Content-Type:` の型トークン欠落 (`; charset=x` のみ) を検出 — `Envelope` に `missing_media_type` を追加 (欄欠落は `missing_content_type`、空値は D1645)。

### Security — D1650: 宛名ドメイン部の空白継続 (`a@b .c`/`a@ b.c`) を検出 — `Envelope` に `ws_domain` を追加。

### Security — D1651: param 値の `=` 直後空白 (`charset= utf-8`) を検出 — `Envelope` に `param_leading_ws` を追加。

### Security — D1652: Date 欄タイムゾーンの空白分断 (`+09 00`) を検出 — `Envelope` に `split_zone` を追加。

### Security — D1645: `Content-Type:`/`Content-Disposition:`/`Content-Transfer-Encoding:` の空値を検出 — `Envelope` に `empty_mime_field` を追加。既定値丸め/欄破棄で読みがずれる (from/date 等の空値は D1435)。

### Security — D1646: 宛名ドメイン部のクオート区間 `a@"b.c"` を検出 — `Envelope` に `quoted_domain` を追加。ドメインは dot-atom/リテラルが正で、受理/構文エラーで宛名がずれる。

### Security — D1647: name/filename 以外の param 値の裸の第二 `=` (`charset=a=b`) を検出 — `Envelope` に `param_eq_bare` を追加 (名札側は D1515)。

### Security — D1648: Date 欄の 4 字以上の月名 (`September`) を検出 — `Envelope` に `long_month` を追加 (未知3字名は D1555)。あわせて D1622 の BAD 集合に `\` を追加し `a@b\c` を捕捉。

### Security — D1641: `Sender:` ありで `From:` 無しの形を検出 — `Envelope` に `sender_no_from` を追加。RFC 5322 は Sender に From を要求し、Sender 採用/欄破棄で差出人表示がずれる。

### Security — D1642: パート側ヘッダの `MIME-Version:` を検出 — `Envelope` に `mimever_in_part` を追加。版欄は最外専用で、パートを拾う/外側のみで MIME 対応判定がずれる (外側欠落は D1289)。

### Security — D1643: アドレス欄ローカル部の裸 `\` (`a\b@c`) を検出 — `Envelope` に `local_backslash` を追加。atext 外の `\` をエスケープ処理/字として読むで宛名がずれる (param 値側は D1624)。

### Security — D1644: CT/CD 欄の name/filename 以外の param 値の生非 ASCII を検出 — `Envelope` に `raw_param_nonascii` を追加。RFC 2231/5987 符号化を要する値を生読み/破棄でずれる (filename は D1510)。

### Security — D1637: 識別子欄 `<…>` 内の残存非合法字 (`|`/`=`/`/`/`,` 等) を検出 — `Envelope` に `msgid_bad_char` を追加。msg-id 字句外の記号を厳格実装が識別子ごと捨て照合ずれ。

### Security — D1638: アドレス欄 `<…>` 内側の `;` (`<a;b@c>`) を検出 — `Envelope` に `addr_angle_semi` を追加。グループ区切りと読む実装と壊れた宛名と読む実装で宛先がずれる (内側 `,` は D1633)。

### Security — D1639: `Date:` の4節時刻 (`12:00:00:30`) を検出 — `Envelope` に `four_part_time` を追加。`time-of-day` は3節までで、切捨て/構文エラーで日付がずれる。

### Security — D1640: アドレス欄 `<…>` 内の途中位置 `"` (`<a "b" @x>`) を検出 — `Envelope` に `mid_angle_quote` を追加。クオートローカル `<"a b"@x>` は合法だが途中位置は非合法 — 開始クオート読み/字読みでずれる。

### Security — D1633: アドレス欄 `<…>` 内側の `,` (`<a@b, c@d>`) を検出 — `Envelope` に `addr_angle_comma` を追加。内側を区切る実装と壊れた単一宛名と読む実装で宛先集合がずれる。

### Security — D1634: アドレス欄の裸トークン途中の `"` (`a"b"@x`) を検出 — `Envelope` に `mid_token_quote` を追加。クオート開始と読む実装と字として読む実装で宛名がずれる。

### Security — D1635: 識別子欄の `<` を伴わない `>` (`a@b>`) を検出 — `Envelope` に `msgid_gt_only` を追加。字として残す実装と捨てる実装で識別子がずれる (開き側のみは D1522)。

### Security — D1636: CT/CD 欄の `;;` 空 param 節を検出 — `Envelope` に `empty_param_segment` を追加。空節を無視する実装と欄ごと捨てる実装で型・名札の読みがずれる。

### Security — D1629: アドレス欄の宛名区切りの全角 `；` (U+FF1B) を検出 — `Envelope` に `addr_fullwidth_semi` を追加。ASCII `;`/`,` のみで分割する実装は宛名を一つと読む (全角コンマは D1537、全角空白は D1583)。

### Security — D1630: 識別子欄 `<…>` 内の生非 ASCII 文字を検出 — `Envelope` に `msgid_nonascii` を追加。msg-id は ASCII 構成のため正規化/拒否でスレッド照合がずれる (encoded-word 形は D1529)。

### Security — D1631: 識別子欄 `<…>` 内のクオート区間 (`<"a b"@x>`) を検出 — `Envelope` に `msgid_quoted_local` を追加。quoted-string は msg-id の字句に無く、剥がす/生採用でずれる。

### Security — D1632: `Date:` の1桁時刻 (`1:2:3`/`1:00`/`12:5`) を検出 — `Envelope` に `date_short_time` を追加。`time-of-day` は 2DIGIT 桁を要求し、丸める/構文エラーで日付がずれる。

### Security — D1625: `Message-ID: <>` の空額縁識別子を検出 — `Envelope` に `msgid_empty_angle` を追加。捨てる実装と匿名識別子として残す実装でスレッド照合がずれる (値自体の空は D1450)。

### Security — D1626: 識別子欄の `<…>` 内 `%`/`!` 経路記号を検出 — `Envelope` に `msgid_routing_char` を追加。経路解釈する実装と生採用する実装で照合キーがずれる (アドレス欄側は D1436)。

### Security — D1627: アドレス欄の額縁外に裸の `@word` 表示語がある形を検出 — `Envelope` に `bare_at_display` を追加。トークン採用と額縁採用で差出人表示がずれる (額縁前の裸アドレスは D1590)。

### Security — D1628: 識別子欄の `<…>` 内側の `;` を検出 — `Envelope` に `semi_in_id` を追加。区切り優先の実装が識別子を途切れさせスレッド照合がずれる (コメント内側は D1603)。

### Security — D1621: `Content-Type: text/plain text/html` の空白区切り二重メディア型を検出 — `Envelope` に `two_media_types` を追加。先採用/後採用/全体エラーで部品の型解釈がずれる (型内空白は D1512)。

### Security — D1622: アドレス欄ドメイン部の DNS 外文字 (`a@b/c.com`) を検出 — `Envelope` に `bad_domain_char` を追加。ラベル構成字外の ASCII を含むドメインを厳格実装が拒否し宛名がずれる (`!`/`%` は D1436)。

### Security — D1623: 識別子欄の全角額縁 `〈a@b〉`/`＜a@b＞`/`【x】` を検出 — `Envelope` に `msgid_fullwidth_angle` を追加。ASCII `<>` のみ拾う実装は識別子を見失う (アドレス欄側は D1549)。

### Security — D1624: CT/CD 欄の非クオート param 値内の `\` (`filename=a\b.txt`) を検出 — `Envelope` に `param_backslash` を追加。エスケープ処理する実装と生採用で添付名がずれる。

### Security — D1617: アドレス欄のコメント `(…)` 内に `@` を含む構造 (`From: ops (ceo@real.com) <x@y>`) を検出 — `Envelope` に `comment_has_addr` を追加。コメントごと走査する実装が別アドレスを拾い差出人表示がずれる (クオート内 `@` は D1602)。

### Security — D1618: アドレス欄のクオート表示名内の `;` (`"Doe; John"`) を検出 — `Envelope` に `quoted_semicolon_display` を追加。クオートを読まずに `;` で切る実装で宛名の切れ目がずれる (CT/CD 版は D1609)。

### Security — D1619: アドレス欄の `<…>` 内側にコメント `(…)` (`From: John <a(note)@b>`) を検出 — `Envelope` に `comment_in_angle` を追加。addr-spec は括弧内 CFWS を許さず剥がす/保持で宛名がずれる (識別子側は D1603)。

### Security — D1620: アドレス欄の空ドメインリテラル `a@[]` を検出 — `Envelope` に `empty_domain_literal` を追加。受理 vs 構文エラーで宛名がずれる (非 IP 中身は D1546)。

### Security — D1613: `Content-Type:` のメディア型トークンに ASCII 大文字 (`TEXT/PLAIN`/`Text/Html`) を検出 — `kaname-render` の `Envelope` に `uppercase_media` を追加。厳密比較実装は小文字形しか拾えず部品の型解釈がずれる (CTE は D1513、param 名は D1495)。

### Security — D1614: `name*=`/`filename*=` の単一 `*=` param 値に `'` が無い形 (`filename*=utf8x`) を検出 — `Envelope` に `star_param_no_apostrophe` を追加。RFC 2231 は `charset'lang'value` を要求し厳格実装が値を捨てる (連番混在は D1530、非数値タグは D1490)。

### Security — D1615: 識別子欄 `<…>` 内の非 IP ドメインリテラル (`Message-ID: <a@[not-an-ip]>`) を検出 — `Envelope` に `msgid_bad_literal` を追加。厳格実装が識別子を捨てスレッド照合がずれる (宛名欄側は D1546)。

### Security — D1616: アドレス欄の表示名が空クオート `""` の形 (`From: "" <a@b>`) を検出 — `Envelope` に `empty_quoted_string` を追加。捨てる実装と空文字採用で差出人の見え方がずれる (語句のみは D1604)。

### Security — D1609: `Content-Type:`/`Content-Disposition:` のクオート値内 `;` (`boundary="a;b"`) を検出 — `kaname-render` の `Envelope` に `quoted_semicolon` を追加。クオートを読まず `;` で割る素朴な実装は値を途中で切る (裸 `;` 異常は D1486)。

### Security — D1610: 日付欄に時刻トークン (`:`) が無い形 (`Date: 25 Sep 2025`) を検出 — `Envelope` に `timeless_date` を追加。深夜扱いする実装と構文エラーとする実装でずれる (ゾーン欠落は D1547)。

### Security — D1611: アドレス欄のコメント入れ子 `((…))` (`From: John ((boss) ceo) <a@b>`) を検出 — `Envelope` に `nested_comment` を追加。浅い除去器は内側を残し表示名の正規化がずれる (未終端は D1521、識別子内は D1603)。

### Security — D1612: encoded-word の連接 (`=?…?=` + 空白 + `=?…?`) を検出 — `Envelope` に `adjacent_encoded_words` を追加。RFC 2047 は間の空白を落とす規定で、厳密処理実装と生表示実装で件名・表示名がずれる。

### Security — D1605: ヘッダブロック先頭が空白/タブ始まりの継続行のみ形を検出 — `kaname-render` の `Envelope` に `orphan_continuation` を追加。folding の元を持たない先頭行で、捨てる実装と本文扱いする実装で欄構成がずれる (空白のみ行は D1599)。

### Security — D1606: アドレス欄の非クオート表示名内 `,` (`From: Doe, John <a@b>`) を検出 — `Envelope` に `unquoted_comma_display` を追加。宛名区切りと読む実装と表示名の一部と読む実装で宛先集合がずれる (連続/端コンマは D1584、語句のみ欄は D1604)。

### Security — D1607: `List-Id:`/`List-Post:`/`List-Subscribe:`/`List-Unsubscribe:`/`List-Help:`/`List-Owner:`/`List-Archive:` の複数回出現を検出 — `Envelope` に `dup_list_headers` を追加。一意前提の欄で先読み/後読みがずれる (宛先欄重複は D1598、一意欄は D1589)。

### Security — D1608: `List-*` 欄の `<`/`>` 数不一致 (`List-Id: <mylist`) を検出 — `Envelope` に `unclosed_list_angle` を追加。行末まで読む実装と欄ごと捨てる実装で解除欄・ML 判定がずれる (裸形は D1601、識別子未終端は D1522)。

### Security — D1601: `List-Post:`/`List-Subscribe:`/`List-Unsubscribe:`/`List-Help:`/`List-Owner:`/`List-Archive:` の値が `<…>` 括弧を欠く裸形 (`List-Unsubscribe: mailto:x`) を検出 — `kaname-render` の `Envelope` に `bare_list_url` を追加。RFC 2369 は `<url>` 形を要求し、厳格実装が操作欄を捨てる (List-Id 裸形は D1572、危険スキームは D1541)。

### Security — D1602: アドレス欄の表示名 (quoted-string) が `@` を含む形 (`From: "ceo@example.com" <attacker@evil>`) を検出 — `Envelope` に `quoted_at_display` を追加。引用部を宛名と誤読する実装で差出人がすり替わる (クオートのみ宛名は D1542、コメント内別アドレスは D1300)。

### Security — D1603: 識別子欄 `<…>` 内の `(` コメント (`Message-ID: <a(x)@b>`) を検出 — `Envelope` に `comment_inside_id` を追加。CFWS は額縁の外のみ合法で、剥がす実装と保持する実装で照合がずれる (端空白 D1516・内側空白 D1596)。

### Security — D1604: アドレス欄が `@` も `<` も持たない語句のみの形 (`From: John Doe`) を検出 — `Envelope` に `display_only_addr` を追加。欄を拒否する実装と語句を名前と推測する実装で差出人がずれる (コメントのみは D1536、グループ構文は対象外)。

### Security — D1597: ヘッダ改行が全て裸 LF (CRLF 皆無) の形を検出 — `kaname-render` の `Envelope` に `lf_only_headers` を追加。CRLF 必須の実装はヘッダ全体を1行と読み、LF 許容実装と欄構成がずれる (行端混在は D1290 系)。

### Security — D1598: `To:`/`Cc:`/`Bcc:`/`Reply-To:` の複数回出現を検出 — `Envelope` に `dup_addr_headers` を追加。結合する実装と先頭/末尾採用で宛先集合がずれる (From/Date 等は D1589、配送欄は D1390)。

### Security — D1599: ヘッダブロック内の空白文字のみ行を検出 — `Envelope` に `blank_ws_line` を追加。継続行と読む実装とヘッダ終端と読む実装で以降の欄が本文落ちするかずれる (コロン無し行は D1585)。

### Security — D1600: CT/CD param 値の未終端 `"` (`boundary="abc`/`charset="x`) を検出 — `Envelope` に `unterm_param_quote` を追加。行末まで読む実装と欄ごと破棄する実装で境界・文字コードの読みがずれる (アドレス欄は D1525)。

### Security — D1593: `Content-Type:`/`Content-Disposition:` の型本体に `,` が混ざる形 (`text/plain, text/html`) を検出 — `kaname-render` の `Envelope` に `comma_media_value` を追加。先の型を採る実装と欄ごと捨てる実装で型解釈がずれる (`;` 裸トークンは D1504、CTE 複数値は D1544)。

### Security — D1594: CT/CD 欄の全角句読点 (`；` U+FF1B / `＝` U+FF1D) を検出 — `Envelope` に `fullwidth_param_punct` を追加。ASCII のみを区切りと見る実装では param が潰れ、正規化する実装では区切りとして読まれる (全角コロン D1581・全角空白 D1583)。

### Security — D1595: 同一 `Content-ID` 値を持つ複数パートを検出 — `Envelope` に `dup_content_id` を追加。RFC 2392 は一意性を要求し、`cid:` 参照を先読み実装と後読み実装で別部品が差し込まれる (欠落参照は D1467)。

### Security — D1596: 識別子欄 `<…>` 内部の空白 (`Message-ID: <a b@c>`/`List-Id: <my list.x>`) を検出 — `Envelope` に `inner_space_id` を追加。空白込みで読む実装と切り詰める実装でスレッド照合・cid 解決がずれる (msgid 端空白は D1516).

### Security — D1589: `From:`/`Date:`/`Subject:`/`Message-ID:` の複数回出現を検出 — `kaname-render` の `Envelope` に `dup_identity_headers` を追加。RFC 5322 では一意欄であり、先読み/後読みで差出人・件名・時刻がずれ、DKIM 署名対象欄としても片方だけが検証される (配送欄重複は D1376、MIME 欄は D1401)。

### Security — D1590: アドレス欄で `<…>` の前に裸アドレスがある形 (`From: a@b <c@d>`) を検出 — `Envelope` に `addr_before_angle` を追加。先の裸宛名を採る実装と額縁内を採る実装で表示される宛名がずれる (額縁後の書き足しは D1538、連続額縁は D1539)。

### Security — D1591: `Date:` の曜日名が `,` 無しの裸形 (`Date: Thu 25 Sep 2025`) を検出 — `Envelope` に `nocomma_weekday` を追加。コンマ必須の実装は曜日を読めず構文エラー、寛容実装は飛ばして日付を拾う (曜日名の綴り違いは D1582、曜日不一致は D1569)。

### Security — D1592: 欄名に ftext 外文字が含まれる形 (`Sub ject:`/`X(1):`/`フロム:`) を検出 — `Envelope` に `bad_ftext` を追加。厳密検査実装が欄ごと捨て、寛容実装が読む (`_` は D1587、`.` は D1548、名と `:` の間の空白は D1305)。

### Security — D1585: ヘッダブロックに `:` を含まない行が混ざる形を検出 — `kaname-render` の `Envelope` に `colonless_header_line` を追加。`X-Junk garbage` のようなコロン無し欄行は、そこでヘッダ解析を打ち切る実装と行を読み飛ばす実装で以降の欄構成がずれる (空白行前コロンは D1305)。

### Security — D1586: `Received:` に必須の `;` 付き日時印が無い形を検出 — `Envelope` に `received_no_semi` を追加。節 (`from/by/with/id/for`) があるのに `;` が無い `Received: from a by b 25 Sep 2025` は、日時印を必須とする実装が欄を捨て寛容実装が拾う (節皆無の手書き形は D1458)。

### Security — D1587: 標準ヘッダ名が `-` でなく `_` で書かれた形 (`Message_ID:`/`Content_Type:`) を検出 — `Envelope` に `underscore_header_name` を追加。欄名を文字通り見る実装では別物の任意欄、`_`→`-` を正規化する実装では標準欄として読まれる (ハイフン欠落は D1473)。

### Security — D1588: `Content-Type:` のメイン型が未登録値の形 (`Content-Type: wednesday/midnight`) を検出 — `Envelope` に `unknown_maintype` を追加。RFC 2045 上 `application/octet-stream` として扱う実装と欄ごと拒否する実装で中身の扱いがずれる (形の崩れは D1356、ワイルドカードは D1540)。

### Security — D1581: 欄名の区切りが全角コロン `：` (U+FF1A) の形を検出 — `kaname-render` の `Envelope` に `fullwidth_colon_header` を追加。`From：a@b`/`Subject：hi` は ASCII `:` だけを区切りと見る実装では欄として認識されず、全角を正規化する実装では通常の欄として読まれる (ハイフン欠落は D1473、ドット混入は D1548)。

### Security — D1582: `Date:` の曜日名が正規の3文字形でない形 (`Monday,`/`mo,`) を検出 — `Envelope` に `bad_weekday` を追加。厳格実装が構文エラーとし寛容実装が曜日を飛ばして日付だけ拾う (曜日と日付の不一致は D1569)。

### Security — D1583: 宛名欄・識別欄に全角スペース U+3000 が混ざる形 (`To: a@b　c@d`) を検出 — `Envelope` に `fullwidth_space_addr` を追加。ASCII 空白以外を語の切れ目と見ない実装と全角空白でも区切る実装で宛先の分割がずれる (全角コンマ D1537・全角＠ D1568)。

### Security — D1584: アドレス欄の宛名リストに空要素が混ざる形 (`a@b,,c@d`/`,a@b`/`a@b,`) を検出 — `Envelope` に `empty_addr_segment` を追加。空要素を無視する実装と不正 mailbox として欄ごと捨てる実装で宛先の集合がずれる (コンマ無し連立は D1539)。

### Security — D1553: ローカル部端ドット検出
**問題** `From: .a@x`/`a.@x` — 端のドットは空 atom で、厳格実装は宛名を拒否・寛容実装は受理してずれる。
**修正** `Envelope.edge_dot_local` — `@` 直前の `.` と先頭 `.` 宛名を検出。
**教訓** 名前の端に点がある表札は、点を名の一部と読む配達人と宛名ごと捨てる配達人がいる。

### Security — D1554: 宛名ドメイン連続ドット検出
**問題** `a@b..c` — 空ラベルのドメインは受理と拒否で宛名がずれる (msgid 版は D1551)。
**修正** `Envelope.dotdot_addr_domain` — `@` 以降の `..` を検出。
**教訓** 番地抜けの宛先は、読み通す配達人と差出人に返す配達人で届き方が違う。

### Security — D1555: 未知月名検出
**問題** `Date: Thu, 25 Foo 2025 …` — 12か月以外の月名は解析を捨てる実装と月を飛ばす実装で日付がずれる。
**修正** `Envelope.bad_month_name` — 日数字直後の英字語が Jan–Dec に無いことを検出。
**教訓** 暦に無い月を書いた消印は、読み飛ばす局と読み誤る局で配達記録がずれる。

### Security — D1556: ローカル部連続ドット検出
**問題** `a..b@x` — 空 atom のローカル部は厳格実装が宛名を捨て寛容実装が受理 (ドメイン側は D1554)。
**修正** `Envelope.dotdot_addr_local` — `@` 前トークンの `..` を検出。
**教訓** 名の途中に抜けた文字がある表札は、名前を読める人と読めない人を分ける。

### Security — D1577: `Date:`/`Resent-Date:`/`Expires:`/`Expiry-Date:` が月先頭の慣習並び (`Sep 25 2025`) の場合を検出 — `kaname-render` の `Envelope` に `month_first_date` を追加。日→月→年の並びしか読めない実装と捨てる実装で日付がずれる (数字月 D1566・曜日不一致 D1569 の姉妹)。

### Security — D1578: `Message-ID:`/`In-Reply-To:`/`References:` の識別子がクオートで括られた形 (`"<a@b>"`) の場合を検出 — `Envelope` に `quoted_msgid` を追加。引用符を剥がして照合する実装と含めて採る実装でスレッド照合がずれる (括弧内空白は D1516)。

### Security — D1579: 宛名ローカル部が RFC 5321 の上限 64 字を超える場合を検出 — `Envelope` に `long_local` を追加。長さを検査する実装と受理する実装で宛名がずれる。

### Security — D1580: 宛名ドメインのラベルが DNS 上限 63 字を超える場合を検出 — `Envelope` に `long_domain_label` を追加。厳格実装が宛名を拒否し寛容実装が受理する (ラベル端の記号は D1560)。

### Security — D1573: `Content-Type:` のメディア型に `/` が2つ以上 (`text/plain/extra`) ある場合を検出 — `kaname-render` の `Envelope` に `multi_slash_ct` を追加。最初の `/` で切る実装と欄ごと捨てる実装で型解釈がずれる (`text//plain` D1511・空白継ぎ D1512・ワイルドカード D1540 と棲み分け)。

### Security — D1574: 宛名ドメインが裸の IPv4 形 (`a@1.2.3.4`) の場合を検出 — `Envelope` に `bare_ipv4_domain` を追加。ドメイン名と読む実装と IP リテラルと見なす実装で宛名がずれる (範囲外は D1564、数値 TLD は D1558)。

### Security — D1575: アドレス欄に全角ピリオド (U+3002 `。`/U+FF0E `．`/U+FF61 `｡`) がある場合を検出 — `Envelope` に `fullwidth_dot_addr` を追加。ASCII 正規化と生読みでドット解釈がずれる (全角＠ D1568・全角括弧 D1549 の姉妹)。

### Security — D1576: `Message-ID:`/`In-Reply-To:`/`References:` の `<…>` 内ローカル部がドットで始まる/終わる (`<.a@x>`/`<a.@x>`) 場合を検出 — `Envelope` に `msgid_edge_dot_local` を追加。空 atom のローカル部を厳格実装は識別子ごと捨てる (連続 `..` は D1567、宛名側は D1553)。

### Security — D1569: `Date:` 欄の曜日名が実日付と一致しない (`Mon, 25 Sep 2025` 等) 場合を検出 — `kaname-render` の `Envelope` に `weekday_mismatch` を追加。曜日を検証する実装と無視する実装で日付の信頼性評価がずれる。

### Security — D1570: 日付欄の年に非数字が混じる (`20x5`/`abcd`) 場合を検出 — `Envelope` に `non_digit_year` を追加。厳格実装が構文エラーとし寛容実装が拾う (2桁年は D1535)。

### Security — D1571: 日付欄のゾーン (`±HHMM`) の後に余分なトークンがある場合を検出 — `Envelope` に `junk_after_zone` を追加。ゾーン以降をエラーとする実装と無視する実装で日付がずれる (省略 D1547、範囲外 D1565)。

### Security — D1572: `List-Id:` が `<…>` 括弧を欠く裸形の場合を検出 — `Envelope` に `bare_list_id` を追加。RFC 2919 の必須括弧を欠き厳格実装は欄ごと捨てる (List-* 群は D1418/D1468)。

### Security — D1565: `Date:`/`Resent-Date:`/`Expires:`/`Expiry-Date:` のタイムゾーンが範囲外 (`+2560`/`+2401` 等、時>14・分>59) の場合を検出 — `kaname-render` の `Envelope` に `bad_tz` を追加。丸める実装と構文エラーにする実装で日付がずれる (省略は D1547、略号は D1534)。

### Security — D1566: 日付欄の月位置が数字 (`25 09 2025`) の場合を検出 — `Envelope` に `numeric_month` を追加。obs-date でしか許されない形を厳格実装は構文エラーとし寛容実装は拾う (未知月名 D1555、日範囲 D1561 の姉妹)。

### Security — D1567: `Message-ID:`/`In-Reply-To:`/`References:` の `<…>` 内ローカル部に連続ドット (`<a..b@x>`) がある場合を検出 — `Envelope` に `msgid_dotdot_local` を追加。厳格実装が識別子を捨てスレッド照合がずれる (ドメイン側 D1551/D1563、宛名側 D1556)。

### Security — D1568: アドレス欄に全角 `＠` (U+FF20/U+FE6B) がある場合を検出 — `Envelope` に `fullwidth_at_addr` を追加。ASCII 正規化する実装と生読みする実装で `@` の認識自体がずれ宛名抽出が壊れる (全角括弧 D1549・全角コンマ D1537 の姉妹)。

### Security — D1561: `Date:`/`Resent-Date:`/`Expires:`/`Expiry-Date:` の日が範囲外 (`32 Sep`/`00 Sep` 等) の場合を検出 — `kaname-render` の `Envelope` に `bad_day` を追加。丸める実装と構文エラーにする実装で日付がずれる (時刻は D1559、月名は D1555 と棲み分け)。

### Security — D1562: 宛名ドメインが `.` で始まる (`a@.b.c`) 場合を検出 — `Envelope` に `leading_dot_domain` を追加。先頭空ラベルは DNS 名として成立せず厳格実装は宛名を拒否する (連続 `..` は D1554)。

### Security — D1563: `Message-ID:`/`In-Reply-To:`/`References:` の `<…>` 内ドメインが `.` で始まる (`<a@.b>`) 場合を検出 — `Envelope` に `msgid_leading_dot` を追加。厳格実装が識別子を捨てスレッド照合がずれる (アドレス欄側は D1562)。

### Security — D1564: 宛名のドット区切り数値リテラルが範囲外 (`a@[999.1.1.1]` の octet>255) の場合を検出 — `Envelope` に `bad_ip_literal` を追加。IPv4 として成立しない値を厳格実装は拒否する (非 IP 形は D1546)。

### Security — D1557: アドレス欄の裸ローカル部に atext 外の特殊文字 (`a/b@x`/`a=b@x`/`a?b@x` の `/` `=` `?` 等) がある場合を検出 — `kaname-render` の `Envelope` に `special_local_char` を追加。厳格実装は宛名を拒否し寛容実装は受理するため、宛名抽出がずれる (連続 `..` は D1556、非 ASCII は D1517 と棲み分け)。

### Security — D1558: 宛名ドメインの最終ラベルが全数字 (`a@b.123`) の場合を検出 — `Envelope` に `digit_tld_addr` を追加。数値 TLD は DNS 名として成立せずフィルタする実装と受理する実装で宛名がずれる (ドット無し数値ドメインは D1507)。

### Security — D1559: `Date:`/`Resent-Date:`/`Expires:`/`Expiry-Date:` の時刻が範囲外 (`25:00`/`12:60` 等) の場合を検出 — `Envelope` に `bad_clock` を追加。丸める実装と構文エラーにする実装で日付がずれる (未知月名 D1555・2桁年 D1535 の姉妹)。

### Security — D1560: 宛名ドメインのラベルが `-` で始まる/終わる (`a@-b.x`/`a@b-.x`) 場合を検出 — `Envelope` に `edge_hyphen_domain` を追加。端ハイフンラベルは DNS 非合法で厳格実装は宛名を拒否する (内部 `_` は D1404)。

### Security — D1549: 全角括弧宛名検出
**問題** `To: 〈a@b〉`/`＜a@b＞` — ASCII `<>` に正規化する実装とそのまま読む実装で宛名抽出がずれる。
**修正** `Envelope.fullwidth_angle_addr` — 宛名欄の `〈〉`/`＜＞` を検出。
**教訓** 額縁の字形が全角になれば、ASCII しか見ない読み手は枠を見失う。

### Security — D1550: 二重 @ 宛名検出
**問題** `a@b@c` — 最初の @ で切る・最後で切る・構文エラーとする実装で宛名がずれる (`a@@b` 連続形は D1408、msgid は D1514)。
**修正** `Envelope.multi_at_addr` — `,` セグメント内の @ 2個を検出 (クオート/コメント除外)。
**教訓** 「2 つの @」は宛名を一つに読めない — どこで切るかが読み手任せになる。

### Security — D1551: msgid ドメイン連続ドット検出
**問題** `Message-ID: <a@b..c>` — 空ラベルの識別子を受理する実装と捨てる実装でスレッド照合がずれる。
**修正** `Envelope.dotdot_msgid_domain` — `<…>` 内 `@` 以降の `..` を検出。
**教訓** 住所の番地が抜けた識別子は、それを読む棚と捨てる棚で綴じが違う。

### Security — D1552: MIME 欄値中 encoded-word 検出
**問題** `Content-Type: =?utf-8?Q?x?=`/`filename="=?…?="` — param 値を復号する実装と生採用する実装で型・名札がずれる。
**修正** `Envelope.ew_in_mime_headers` — CT/CD/CTE 欄値の `=?` を検出。
**教訓** 種類札に暗号が書かれていては、復号する受付と字のまま読む受付で品物が違う。

### Security — D1545: msgid 欄の括弧後ゴミ検出
**問題** `Message-ID: <a@b> junk` — 括弧内だけ採る実装と残りを識別子に連ねる実装でスレッド照合がずれる (宛名欄版は D1538)。
**修正** `Envelope.msgid_junk_after_angle` — 最終 `>` 以降の残存を検出。
**教訓** 整理番号の額縁の外に書き足された文字は、番号の一部と読む棚と読まない棚でずれる。

### Security — D1546: 非 IP ドメインリテラル検出
**問題** `From: a@[not-an-ip]` — `[…]` が IP を含まず、リテラル受理と拒否で宛名がずれる (IP 形は D1407)。
**修正** `Envelope.nonip_domain_literal` — `[…]` 内が数値/IPv6 形でない宛名を検出。
**教訓** 地図の緯度経度欄に名前を書くと、座標として読む配達人と捨てる配達人がいる。

### Security — D1547: ゾーン無し Date 検出
**問題** `Date: Thu, 25 Sep 2025 12:00:00` ゾーン欠落 — ローカル時刻扱いと構文エラーで日付がずれる (名前ゾーンは D1534)。
**修正** `Envelope.zoneless_date` — Date 系欄末尾のゾーン欠落を検出。
**教訓** 時刻帯の書かれていない消印は、読む場所で「今日」の境界がずれる。

### Security — D1548: ドット欄名検出
**問題** `Content.Type:`/`X.Original-From:` — ハイフンの代わりのドットは欄名文字として拒否する実装と許す実装で欄がずれる (ハイフン欠落は D1473)。
**修正** `Envelope.dotted_header_name` — `:` 前の欄名中 `.` を検出。
**教訓** 欄名の綴りに点を打つ癖は、それを綴りと認める係と欄ごと捨てる係を分ける。

### Security — D1541: `List-*` 危険スキーム検出
**問題** `List-Unsubscribe: <javascript:alert(1)>` — 規格は mailto/https のみ想定だが、ワンクリック解除を実装したクライアントは任意スキームを開き得る。
**修正** `Envelope.dangerous_list_scheme` — `List-*` 欄の `javascript:`/`data:`/`file:`/`vbscript:` 等を検出。
**教訓** 窓口票に書けるのは郵便かウェブの住所だけ — それ以外の言語は実行される罠になる。

### Security — D1542: クオートのみ宛名検出
**問題** `From: "a@b"` — 括弧も裸宛名も無く、クオート内を宛名と読む実装と空を返す実装で差出人がずれる (注釈のみは D1536)。
**修正** `Envelope.quoted_only_addr` — 全体が `"…"` の宛名欄を検出。
**教訓** 吹き出しだけが残った封筒は、台詞を宛名と読むか宛名無しとするかで分かれる。

### Security — D1543: 未終端グループ構文検出
**問題** `To: team: a@b` — グループの `:` が `;` で閉じず、構文エラーとする実装と行末で自動閉じる実装で宛先がずれる (`;` 混入は D1523)。
**修正** `Envelope.unclosed_addr_group` — クオート/コメント/括弧外の `:` で `;` 無しを検出。
**教訓** 「班:」と開いた名簿が閉じ印のまま終わると、班員として読む人と無効とする人がいる。

### Security — D1544: 複数値 CTE 検出
**問題** `CTE: base64, quoted-printable` — 先頭採用・末尾採用・破棄で復号の有無がずれる (欄重複は別系、`;` 継ぎゴミは D1405)。
**修正** `Envelope.multi_value_cte` — `,` で区切られた2つ目の非空値を検出。
**教訓** 「BASE64 か QP か」二枚重ねの符号化指定は、読む順によって別の手紙を取り出す。

### Security — D1537: 全角コンマ区切り宛名検出
**問題** `To: a@b，c@d` — ASCII `,` のみ切る実装は壊れた一宛名、全角も切る実装は二宛名。
**修正** `Envelope.fullwidth_comma_addr` — 宛名欄の `，`/`、` を検出。
**教訓** 仕切りの字形が違えば、宛名簿の行数も違って読まれる。

### Security — D1538: 括弧後ゴミ検出
**問題** `From: <a@b> junk` — 括弧内だけ採る実装と後のゴミも宛名に連ねる実装で差出人がずれる。
**修正** `Envelope.addr_junk_after_angle` — 最後の `>` 以降の非`,`残存を検出。
**教訓** 名札の額縁の外に書き足された文字は、額縁だけ見る人と全体を読む人で意味が違う。

### Security — D1539: コンマ無し連続括弧宛名検出
**問題** `To: <a@b> <c@d>` — 括弧ごと採る実装は二宛名、`,` のみ区切る実装は壊れた一宛名 (空白継ぎ裸宛名は D1531)。
**修正** `Envelope.two_angles_no_comma` — セグメント内の `<…> <…>` 二組を検出。
**教訓** 額縁が二つ並ぶだけでは宛名は二つ — 間の仕切りを読むかが分かれる。

### Security — D1540: ワイルドカード Content-Type 検出
**問題** `Content-Type: */*`/`text/*` — メッセージで非合法の型指定を既定値に読み替える実装と捨てる実装で本文の扱いがずれる (空の型側は D1511)。
**修正** `Envelope.wildcard_ct` — `*/*`・`xxx/*`・`*` の型欄を検出。
**教訓** 「何でも」という種類指定は、受け取る側に「どれか」を選ばせる — 選ぶ側ごとに中身が変わる。

### Security — D1533: 二重コロン欄名検出
**問題** `From:: a@b`/`X-Foo::` — 末尾 `:` を許す実装と構文エラーにする実装で以降の全欄がずれる。
**修正** `Envelope.double_colon_header` — 欄名末尾/直後の `:` を検出。
**教訓** 欄名の綴りが1記号ずれるだけで、書類全体の読み分けが割れる。

### Security — D1534: 名前付きタイムゾーン検出
**問題** `Date: … 12:00:00 JST` — obs-zone 外の略名は既知名だけ解釈する実装と捨てる実装で時刻がずれる。
**修正** `Envelope.named_zone` — Date 系欄末尾の非標準英字ゾーンを検出。
**教訓** 消印の時刻帯に私製の略号を書くと、読める局と読めない局で配達記録が割れる。

### Security — D1535: 2桁年検出
**問題** `Date: 25 Sep 25` — obs-year のピボット (00–49→2000年代、50–99→1900年代) を知る実装と素読みする実装で日付がずれる。
**修正** `Envelope.two_digit_year` — Date 系欄の2桁年を検出。
**教訓** 年号の桁を省いた書き付けは、読み手の生まれた時代で解釈が割れる。

### Security — D1536: コメントのみ宛名検出
**問題** `From: (notes)` — 宛名抽出が空になる実装と注釈を差出人表示に流用する実装で差出人がずれる (空値は D1450)。
**修正** `Envelope.comment_only_addr` — コメント剥がし後に残るものが無い宛名欄を検出。
**教訓** 余白の走り書きだけの封筒は、それを宛名と読む配達人を生む。

### Security — D1529: 識別子欄内の encoded-word 検出
**問題** `Message-ID: <=?utf-8?B?eA==?=@h>` — 復号して照合する実装と生のまま採る実装で識別子がずれスレッドが壊れる。
**修正** `Envelope.msgid_encoded_word` — msgid 系欄の `=?` を検出。
**教訓** 名札の中の符号化は照合ごとに姿を変える — 復号の有無で同一性が割れる。

### Security — D1530: 2231 連番の素/星混在検出
**問題** `filename*0=a; filename*1*=b` — `*=` のみ解釈する実装と全連結する実装で添付名がずれる (欠番は D1394)。
**修正** `Envelope.mixed_2231_cont` — 同基底名の `*N=` と `*N*=` 混在を検出。
**教訓** 分冊の綴じ方が途中で変わると、読み継ぐ実装と選別する実装で名札が違う。

### Security — D1531: 空白継ぎの裸宛名検出
**問題** `To: a@b c@d` — `,` だけを区切る実装は壊れた一宛名、空白でも切る実装は二宛名 (`,` 無し複数宛名は非規格形)。
**修正** `Envelope.spaced_bare_addrs` — 括弧・クオート・コメント外の `tok@ tok@` を検出。
**教訓** 区切りを書き忘れた宛名簿は、読み手ごとに人数が違う。

### Security — D1532: `@` 無し Content-ID 検出
**問題** `Content-ID: <abc>` — msgid 形でない識別子は厳密照合の実装で cid: 参照が解決不能 (括弧欠落は D1395)。
**修正** `Envelope.atless_content_id` — `<…>` 内の `@` 欠落を検出。
**教訓** 図版の番号札が住所を欠いていると、指し示す側と辿る側で絵が分かれる。

### Security — D1525: 宛名欄の未終端クオート検出
**問題** `From: "John <a@b>` — 行末まで quoted-string と読む実装と欄ごと捨てる実装で宛名がずれる (コメント未終端は D1521)。
**修正** `Envelope.unclosed_addr_quote` — コメント外 `"` の対応欠落を検出。
**教訓** 閉じない引用符は宛名の終わりを溶かす — 名札の輪郭が実装で違う。

### Security — D1526: 宛名欄の括弧崩れ検出
**問題** `From: <a@b`/`a@b>` — 未終端・裸括弧で行末読みと構文エラーが分かれる (空括弧 D1508・入れ子 D1500・msgid 側 D1522)。
**修正** `Envelope.unclosed_angle_addr` — クオート・コメント外の `<`/`>` 対応崩れを検出。
**教訓** 括弧の前後が揃わなければ宛名の輪郭が割れる。

### Security — D1527: encoded-word の危険 charset 検出
**問題** `=?utf-7?Q?x?=`/`=?utf-16?B?…`/`=?x-user-defined?` — 復号器の charset 解釈で件名・差出人表示が変わる (欄 charset は D1301、`*=` は D1524、混在は D1372)。
**修正** `Envelope.bad_ew_charset` — `=?…?` の charset 部を危険リストで検査。
**教訓** 符号化の扉は3箇所目 — encoded-word 内の辞典も汚れうる。

### Security — D1528: `@` 無し括弧宛名検出
**問題** `From: John <backup>` — 括弧内を宛名と採る実装と全体を読む実装で宛名がずれる (空括弧は D1508)。
**修正** `Envelope.atless_angle_addr` — クオート・コメント外 `<…>` の `@` 欠落を検出。
**教訓** 宛名の枠だけあって住所が無い — 枠を信用する実装だけが値を採る。

### Security — D1521: 宛名欄の未終端コメント検出
**問題** `From: a@b (notes` — 行末までコメントと読む実装と欄ごと捨てる実装で宛名がずれる (コメント内宛名は D1300)。
**修正** `Envelope.unclosed_addr_comment` — クオート外 `(` の対応欠落を検出。
**教訓** 閉じない注釈は後続を全部飲み込む — 書き漏らしが宛名を消す。

### Security — D1522: 識別子の未終端括弧検出
**問題** `Message-ID: <a@b` — 行末まで識別子と読む実装と捨てる実装でスレッド照合がずれる。
**修正** `Envelope.unclosed_msgid` — `<` に対応 `>` が無い形を検出 (構造崩れの D1498 と別の開閉欠落)。
**教訓** 開きっぱなしの名札枠は読み終わりが実装ごとに違う。

### Security — D1523: 宛名欄の裸セミコロン検出
**問題** `From: a@b; c@d` — グループ終端記号を区切りと読む実装と構文エラーとする実装で宛名がずれる (グループ構文は D1363/D1446)。
**修正** `Envelope.semicolon_addr` — クオート・コメント・括弧外の `;` を検出。
**教訓** 別名簿の区切り記号を宛名簿に持ち込むと読み方が割れる。

### Security — D1524: `*=` パラメータの危険 charset 検出
**問題** `filename*=utf-16''x`/`utf-7''` — 復号器の charset 解釈で名札の綴りが変わる (ヘッダ charset 危険値は D1301)。
**修正** `Envelope.bad_2231_charset` — `*=` 値の charset 部を危険リストで検査。
**教訓** 符号化の扉が2箇所ある — 添付名側の辞典も汚れうる。

### Security — D1517: 宛名ローカル部の非 ASCII 検出
**問題** `café@x` の非 ASCII ローカル部 — SMTPUTF8 を解釈する実装は有効宛名、ASCII のみ認める実装は宛名ごと捨てる (ドメイン側は D1359)。
**修正** `Envelope.nonascii_addr_local` — アドレス欄の `@` 手前部の非 ASCII を検出。
**教訓** @ の手前にも文字コードの海峡がある — 渡れる実装と渡れない実装で差出人が分かれる。

### Security — D1518: dot-stuffing 残渣検出
**問題** 本文の `..` 始まり行 — SMTP 重ねドット (RFC 5321 §4.5.2) を戻す実装とそのまま見せる実装で行頭がずれる (単独 `.` は D1421)。
**修正** `Envelope.dot_stuffed_line` — 本文中の `..`+非ドット行を検出 (`...` のみは対象外)。
**教訓** 配送の跡が残る文は、復元する側とそのまま読む側で綴りが違う。

### Security — D1519: 大文字形開け方指定検出
**問題** `Content-Disposition: Attachment`/`INLINE` — 小文字厳密比較の実装は添付として認識しない (非標準型は D1337)。
**修正** `Envelope.mixed_case_disposition` — attachment/inline の大小写違いを検出。
**教訓** 字体違いの指示書は従う実装と読まない実装で添付の扱いが分かれる。

### Security — D1520: 符号化名内空白検出
**問題** `CTE: base 64` の値内空白 — 除去して読む実装と未知値で捨てる実装で復号の有無がずれる (大文字形は D1513)。
**修正** `Envelope.spaced_cte` — CTE 値の内部 WSP を検出。
**教訓** 符号化名の真ん中の隙間は継ぎ足しと切り捨てで読みが分かれる。

### Security — D1513: 大文字形符号化指定検出
**問題** `CTE: BASE64`/`Quoted-Printable` — 規格上大小写不問だが、厳密に小文字比較する実装は「未知の符号化」として復号せず本文が丸ごとずれる。
**修正** `Envelope.mixed_case_cte` — 既知名の大小写違いのみを検出 (未知値は D1502、ゴミ付きは D1405)。
**教訓** 名札の綴りが同じでも字体が違えば読み捨てる側がある — 大文字小文字は照合の落とし穴。

### Security — D1514: 識別子の複数 @ 検出
**問題** `Message-ID: <a@b@c>` — 最初/最後の `@` で切る実装と全体採用で識別子がずれスレッド照合が壊れる (0 個・端 `@` は D1498)。
**修正** `Envelope.multi_at_msgid` — `<…>` 内の 2 個以上の `@` を検出。
**教訓** 継ぎ目の記号が2つあると切断位置が揺れる — 識別子の一意性が崩れる。

### Security — D1515: パラメータ値内の裸 = 検出
**問題** `filename=a=b` — 最初の `=` で切る実装と全 `=` で切る実装で名・値がずれる (クオート内 `=` は正当)。
**修正** `Envelope.extra_eq_param` — クオート scrub 後の `;` セグで 2 個目の `=` を検出。
**教訓** 仕切り記号が値の中に紛れると、名と値の境界が揺れる。

### Security — D1516: 識別子の括弧内空白検出
**問題** `Message-ID: < a@b >`/`<a b@c>` — trim 実装と空白を含めて採る実装・捨てる実装で識別子がずれる。
**修正** `Envelope.spaced_msgid` — `<…>` 内の WSP を検出。
**教訓** 名札枠の中の余白は「読み込むか削るか」で識別子が分かれる。

### Security — D1509: QP 符号化平文部品の HTML 検出
**問題** `text/plain` + `quoted-printable` 部品の復号結果が `<html>`/`<a href>` — 復号表示 vs 推測描画でずれる (D1505 の QP 版)。
**修正** `Envelope.qp_html_part` — QP ソフト改行を畳んで復号し HTML マーカを検査 (部品・単一部品本文両対応)。
**教訓** 符号化方式が違っても狙いは同じ — 名札の型と復号後の実体を両方見る。

### Security — D1510: 添付名の生非 ASCII 検出
**問題** `filename="café.pdf"` の生高位バイト — Latin-1 読み・UTF-8 読み・拒否で名札がずれる (`*=` 符号化形は D1396、制御バイトは D1506)。
**修正** `Envelope.raw_nonascii_filename` — 素の `filename=`/`name=` 値の非 ASCII を検出。
**教訓** 符号化宣言の無い文字は読み手の推測次第 — 同じ名札が実装ごとに別の綴りになる。

### Security — D1511: 空の型・サブタイプ検出
**問題** `text/`/`/plain`/`text//plain` — `/` があるが片側が空。既定値を当てる実装と欄ごと捨てる実装で型がずれる (`/` 皆無は D1320)。
**修正** `Envelope.edge_slash_ct` — メディア型トークンの空側・二重スラッシュを検出。
**教訓** 区切りだけあって名が無い — 形を借りた空白は読み分けを生む。

### Security — D1512: 型トークン内空白検出
**問題** `text /plain`/`multipart/ mixed` の型内部空白 — 空白除去 vs 捨てる実装で型解釈がずれる (param 領域の空白継ぎは D1501)。
**修正** `Envelope.spaced_media_type` — メディア型トークン内部の WSP を検出。
**教訓** 名札の真ん中の隙間は結合か切断かで読みが分かれる。

### Security — D1505: 平文名札の符号化 HTML 検出
**問題** `text/plain` + `base64` 部品の復号結果が `<html>`/`<a href>` — 復号して文字列表示する実装は安全に見えるが、推測描画する実装では対話フォームが動く (D1481 の符号化版)。
**修正** `Envelope.b64_html_part` — 部品単位・単一部品本文の両方で b64 復号し HTML マーカを検査。
**教訓** 「復号してみると別の顔」は符号化が検査の視界を遮る形 — 名札の型と中身の実体を両方見る。

### Security — D1506: 添付名の生制御文字検出
**問題** `filename="a\x01b.exe"` の非印刷バイト — 保存時に除去する実装と残す実装で名札がずれる (符号化形は D1396)。
**修正** `Envelope.ctl_filename` — 素の `filename=`/`name=` 値の制御バイト (HT・符号化形を除く) を検出。
**教訓** 見えない文字は名札の形を変える — 除去する側と残す側で同一ファイル名が分かれる。

### Security — D1507: ドット無し差出人ドメイン検出
**問題** `From: a@mail`/`a@localhost` のドット無しドメイン — 拒否・表示・組織内ドメイン推測で差出人の読みがずれる (IP リテラルは D1370、`_` は D1404、末尾ドットは fqdn_trailing_dot)。
**修正** `Envelope.dotless_sender_domain` — From/Sender/Resent-* の addr-spec ドメインのドット欠落を検出。
**教訓** ピリオドの無い宛先は「どこの誰か」が曖昧 — 組織内推測する実装では外部者が内部者の顔をする。

### Security — D1508: 空の宛名括弧検出
**問題** `From: "x" <>` — 中身の無い括弧は括弧内を採る実装で宛先が消え、全体を読む実装で残骸が残る (片側欠落は D1408、識別子欄の `<>` は D1498)。
**修正** `Envelope.empty_angle_addr` — アドレス欄のクオート・コメント外 `<>` を検出 (Return-Path の `<>` はバウンス正規形なので対象外)。
**教訓** 空の名札枠は「名札あり」の体裁だけを残す — 採用する側と落とす側で宛名がずれる。

### Security — D1501: 空白区切りのパラメータ継ぎ検出
**問題** `Content-Type: text/plain charset=utf-8` — `;` を欠いて空白で継ぐ形は、`;` で区切る実装に「param 無し」と見え、空白で区切る実装に charset 有りと見える。
**修正** `Envelope.space_separated_param` — CT/CD の型トークン区間 (最初の `;` 手前) の空白後 `=` を検出 (クオート内除外)。
**教訓** 区切り記号を忘れた継ぎは、読み方によって param の存否が変わる。

### Security — D1502: 規定外符号化名の検出
**問題** `Content-Transfer-Encoding: uuencode`/`binhex`/`yenc` — 未知値を素通しにする実装と既定 7bit 扱いの実装で本文の見え方がずれる。
**修正** `Envelope.unknown_cte` — 既知集合外かつ `x-` 非接頭の単一トークン値を検出 (ゴミ付きは D1405、空値は D1451)。
**教訓** 辞書に無い符号化名は、引き受けるか落とすかが実装差 — `x-` 拡張だけが規定の抜け道。

### Security — D1503: 容器の中の容器検出
**問題** `multipart/alternative` のメンバーに `multipart/alternative` — 内側に降りる実装と部品として扱う実装で本文がずれる。
**修正** `Envelope.nested_alternative` — alternative のメンバー部品の CT が alternative なら検出 (related/mixed は正当)。
**教訓** 「読み比べる束」の中に「読み比べる束」は再帰の誤用 — 部品化と降下で見えるものが違う。

### Security — D1504: 裸トークンのパラメータ検出
**問題** `Content-Disposition: attachment; inline` — `=` を持たない裸トークンは値なし param かゴミかで実装が分かれる (空名 `;=` は D1420、行末/連続 `;` は D1486)。
**修正** `Envelope.bare_param` — クオート区間を潰した上で `;` 区切り片の `=` 無し非空を検出。
**教訓** `=` を欠く継ぎ目のトークンは param か誤植か曖昧 — 曖昧さは実装差の温床。

あわせて `has_dash_boundary` を拡張 — `-x` のように `-` で始まる boundary 値 (区切り行 `---x`) も捕捉。

### Security — D1497: 素と拡張の名札併記検出
**問題** `filename="a"; filename*="b"` — RFC 2231 は拡張形優先と規定するが、素の形を採る実装・後勝ちの実装では添付名がずれる。
**修正** `Envelope.ext_and_plain_param` — クオート区間を潰した上で同名基底の素/拡張併記を検出。
**教訓** 「同じ欄が二つの書式で」も一種の重複 — 採用規則の違いが名札の読みを分ける。

### Security — D1498: 住所欠けの識別子検出
**問題** `Message-ID: <abc>` / `<a@>` / `<@h>` / `<>` — local@domain の一方を欠く識別子は厳格実装が捨て、寛容実装が拾う。
**修正** `Envelope.broken_msgid_spec` — message-id/in-reply-to/references/resent-message-id の `<…>` 内の local@domain 欠落を検出。
**教訓** 括弧があるだけでは足りない — 中身の addr-spec の形まで規格の約束。

### Security — D1499: obs-route 経路指定の検出
**問題** `From: <@r1,@r2:user@host>` — obs-route を解釈する実装は末端の宛名だけを見、解釈しない実装は全体を一つの名として見る。
**修正** `Envelope.route_addr` — アドレス欄の `<…>` 内で `:` 前置が `@` 始まりになる経路指定を検出 (%/! 経路は D1436)。
**教訓** 「通ってきた道順の記述」は宛名ではない — 混ぜると実装間で名指しがずれる。

### Security — D1500: アドレス欄の入れ子括弧検出
**問題** `From: <<a@b>>` — 括弧を1層剥がす実装と全部剥がす実装で宛名がずれる (Message-ID 入れ子は D1480)。
**修正** `Envelope.nested_angle_addr` — アドレス欄のクオート・コメント外で `<<`/`>>` を検出。
**教訓** 入れ子の形そのものが実装差の温床 — 名札の括弧は一層が規格。

### Security — D1493: 名札側空白のパラメータ検出
**問題** `boundary = "x"` — param 名末尾の空白を trim する実装は拾い、厳格実装は未知キーとして捨てる (構造情報の喪失)。`= の直後の空白` は D1487。
**修正** `Envelope.spaced_param_name` — クオート区間を潰して `=` 直前の空白を検出。
**教訓** キーと `=` の間の空白も構文違反 — trim の有無で param の存否が変わる。

### Security — D1494: 同型代替メンバーの重複検出
**問題** `multipart/alternative` に同じ基底型のメンバーが二度現れると、「最初を採用」と「最後を採用」で見せる本文がずれる (順序差異は D1454)。
**修正** `Envelope.dup_alternative_part` — alternative のメンバー基底型を列挙し重複を検出 (CT 無し部品は既定 text/plain)。
**教訓** 「別表現」の約束は型の一意性を含む — 同型の二度目はどちらが本物か実装に委ねられる。

### Security — D1495: 大文字混じりのパラメータ名検出
**問題** パラメータ名は case-insensitive — `FILENAME=`・`Name=` を畳まない実装は添付名を見逃す。
**修正** `Envelope.mixed_case_param` — CT/CD の param キー (連番タグ除く) の大文字を検出。
**教訓** 大小写の正規化は暗黙の前提 — 畳まない実装では名札が読めない。

### Security — D1496: text を欠く alternative 検出
**問題** `multipart/alternative` のメンバーに text/* が一つも無いと、「最初の部品を描く」実装と「添付一覧に落とす」実装で見え方がずれる。
**修正** `Envelope.alternative_no_text` — メンバー基底型を列挙 (CT 無しは既定 text/plain) し text の有無を検査。
**教訓** 「読める代替」がひとつも無い束は構造の誤用 — 添付混入 (D1343) とは別の死角。

### Security — D1489: パート本文先頭の BOM 検出
**問題** パート本文が BOM (`EF BB BF`/`FF FE`/`FE FF`) で始まると、BOM を優先する実装と charset 宣言を優先する実装で文字コード解釈がずれる (UTF-16 BOM なら内容ごと見えなくなる)。メッセージ先頭は D1342。
**修正** `Envelope.part_bom` — ヘッダ区切り (`\n\n`/`\r\n\r\n`) 直後のバイト列を検査。
**教訓** BOM の優先順位は規格が曖昧 — 「先頭」の意味も実装でずれる。

### Security — D1490: 異常な連番 param タグ検出
**問題** `*=` の裸星や `filename*foo=` の非数値タグは、RFC 2231 を厳格に解釈する実装で捨てられ、寛容実装は拾う (欠番は D1394)。
**修正** `Envelope.bad_star_param` — CT/CD の param キーの `*` 以降が空・数字・数字+`*` の正規形に合わない形を検出。
**教訓** 連番の「タグ」部分も構文規則の内 — 規格外タグは拾う実装と捨てる実装を分かつ。

### Security — D1491: 閉じ区切りの重複・逆順検出
**問題** 同一 boundary の `--b--` が 2 回以上、または開き `--b` より前に現れると、「最初の閉じで全て終了」と読む実装と「拾い続ける」実装で構造がずれる (閉じのみは D1483)。
**修正** `Envelope.double_closer` — 開きが存在する上で閉じが二重・先行する形を検出。
**教訓** 「閉じ印」は1回限りのはず — 再出現はパーサの状態遷移を実装ごとに分かつ。

### Security — D1492: msgid 内の非 ASCII 検出
**問題** `Message-ID: <café@x>` — msgid は ASCII 構文なので、厳格実装は識別子ごと捨て、寛容実装は採用する (スレッド照合のずれ)。
**修正** `Envelope.nonascii_msgid` — Message-ID/In-Reply-To/References/Resent-Message-ID の `<…>` 内を検査 (生 UTF-8 全般は D1304)。
**教訓** 識別子は照合の要 — 採用/棄却の分岐は実装の寛容度に依存する。

### Security — D1485: 大小写違いの区切り行検出
**問題** boundary は case-sensitive — `boundary=b` と宣言されながら本文に `--B` が現れると、厳密比較する実装は部品を見ず、正規化する実装は切り出す。
**修正** `Envelope.case_variant_boundary` — 宣言値の完全一致を除き、大小写を畳んだ時だけ一致する区切り行を検出。
**教訓** 「ほぼ同じ区切り」はパーサ実装の分岐点 — case-fold する実装が存在する限りずれは残る。

### Security — D1486: ぶら下がりパラメータ区切り検出
**問題** `Content-Type: text/plain;` — 区切り `;` の後に何も無い (または `;;` 連続) と、「パラメータを期待してエラー」と「読み飛ばす」で型解釈がずれる。
**修正** `Envelope.dangling_param_semi` — クオート区間を潰して `;` 末尾・`;;` 連続を検出 (`;=` 空名は D1420)。
**教訓** 区切り記号の終端も構文の一部 — 残りを期待する実装と寛容な実装でずれる。

### Security — D1487: 空白を挟んだパラメータ値検出
**問題** `filename= "a.exe"` — `=` の直後の空白を値の一部と読む実装と、飛ばして値を読む実装で添付名がずれる。
**修正** `Envelope.spaced_param_value` — クオート区間を除いた `= ` / `=	` を検出。
**教訓** 構文の空白許容は規格ごとに狭い — つい読み飛ばす実装の方が多いためずれが出る。

### Security — D1488: 本体なき List-Unsubscribe-Post 検出
**問題** RFC 8058 の `List-Unsubscribe-Post:` は `List-Unsubscribe:` 機構への振る舞い指定 — 本体無しでは「ワンクリック」の体裁だけ残る (Gmail 等はボタン表示の根拠に使う)。
**修正** `Envelope.orphan_unsubscribe_post` — Post 欄あり・Unsubscribe 欄無しを検出 (孤児 List-* は D1468)。
**教訓** 修飾欄は本体があって初めて意味を持つ — 単独で現れる修飾は偽装の形跡。

### Security — D1481: 平文部品の HTML 混入検出
**問題** `Content-Type: text/plain` の本文に `<html>`/`<a href=`/`<form>` 等が含まれると、型を厳守する実装は文字列を表示し「親切」に HTML と推測する実装は対話可能なフォームとして描画する — 安全と名乗る型の下に活動性コンテンツが潜む。
**修正** `Envelope.html_in_plain_part` — パート run ごとに CT 基底型と本文を対応づけ、text/plain 本文のマークアップを検出。
**教訓** 「text/plain は安全」は実装依存 — 推測描画する実装が存在する限り型宣言は安全保証でない。

### Security — D1482: 欄違いの名札パラメータ検出
**問題** `filename=` が Content-Type 行に、`name=` が Content-Disposition 行に置かれると、欄の正規パラメータだけを読む実装と横断して拾う実装で添付名がずれる。
**修正** `Envelope.misplaced_attachment_param` — CT/CD 行のパラメータキーを走査し逆配置を検出。
**教訓** 「どの欄にどのパラメータ」も実装差異の源 — 寛容実装は RFC を越えて拾う。

### Security — D1483: 閉じ区切りのみの multipart 検出
**問題** 宣言 boundary が `--b--` (閉じ) のみで `--b` (開き) が一度も現れない → 部品ゼロの空容器。閉じ区切りだけで multipart と判断する実装と部品を探し続ける実装で構造がずれる (D1460 は boundary 完全不使用)。
**修正** `Envelope.closer_only_multipart` — 開き/閉じ区切りを別々に数え、開き0・閉じ1以上を検出。
**教訓** 「区切りが使われている」だけでは不十分 — 開きと閉じのペアで意味が決まる。

### Security — D1484: ヘッダ値の素 QP 断片検出
**問題** `Subject: half=20baked` のように encoded-word 外の `=XX` がヘッダ値に現れると、QP 復号を適用する実装としない実装で表示がずれる (encoded-word 内部の制御は D1324)。
**修正** `Envelope.stray_qp_header` — 表示欄 (Subject/From/To 等) の値から `=?…?=` を除き `=hexhex` を検出。
**教訓** 欄値の「たまたま QP らしい形」も復号差異の種 — 対象欄の限定で誤爆を避ける。

### Security — D1477:

- **問題**: `X-Original-Message-ID:`/`X-Original-From:`/
  `X-Original-Subject:`/`X-Original-Date:` 等の「元の値」欄 —
  書き換え前の真の値の露出と、存在しない「元の体裁」の捏造の
  両方に使われる (X-Original-To/-Sender/-ArrivalTime は MTA
  記録印の群で検出済み)。
- **修正**: `has_original_headers` が元の値を名乗る欄を検査する。
- **教訓**: 「元はこうでした」の添え書き — 書き換え前の真実を
  明かすものと、無かった過去を作るものとがある。

### Security — D1478:

- **問題**: `DomainKey-Signature:`/`DomainKey-Status:`/`X-DKIM:`/
  `X-DKIM-Signature:`/`X-DomainKey*:` — DomainKeys は RFC 4870 で
  DKIM に置き換えられた旧制度で現行では検証不能、「封印済み」の
  体裁だけ残る (dkim=pass の対象欠落は D1433)。
- **修正**: `has_obsolete_signature_headers` が廃止・模倣の署名欄
  を検査する。
- **教訓**: 昔の制度の朱肉 — 現行の鑑定では読めない「捺印済み」の
  体裁は誰でも作れる。

### Security — D1479:

- **問題**: `Archived-At:`/`X-Archived-At:`/`X-Mail-Archive-*` —
  RFC 5064 の「原本の保存場所」URL 欄。本文 URL 集めに含めない
  スキャナの隙間を通る誘導リンクで、「原本」の体裁が別メッセージ
  への差し替えを可能にする (Content-Description 内 URL は D1475)。
- **修正**: `has_archive_claim` が原本参照欄を検査する。
- **教訓**: 「原本はあちらに」という指示札 — 示された先が本物の
  原本かは誰も確かめない。

### Security — D1480:

- **問題**: `Message-ID: <<a@b>>`/`References: <<c@d>>` — 識別子の
  入れ子括弧。括弧を1層剥がす実装と全部剥がす実装で識別子がずれ、
  スレッド照合が壊れる (`<a><b>` 連立は D1414、`<` 無しは D1461)。
- **修正**: `has_nested_msgid` が識別子値の `<<`/`>>` を検査する。
- **教訓**: 二重の額縁 — 一層剥がす係員と全部剥がす係員で
  中の絵が違う。

### Security — D1473:

- **問題**: `MessageID:`/`InReplyTo:`/`MIMEVersion:`/
  `ContentType:`/`ListID:` 等のハイフン欠落した標準欄の綴り違い
  — 欄名を厳格一致する実装では認識されず、正規化して拾う実装で
  は機能するため、スレッド判定・構造判定・一意欄判定が実装間で
  ずれる (欄名中の空白・非ASCIIは D1448)。
- **修正**: `has_unhyphenated_header` が既知欄の綴り違い形を検査。
- **教訓**: 綴りを一文字崩した欄名は、字を正す係員には働き、
  字通りの係員には働かない — 判読するか捨てるかで分かれる。

### Security — D1474:

- **問題**: `Content-Transfer-Encoding: "base64"` — mechanism は
  トークン型が規格だが引用符付きで書かれた欄は、引用符を剥がす
  実装と欄ごと拒否する実装で復号の有無がずれる (メディア型の
  引用符は D1417 が担当)。
- **修正**: `has_quoted_cte` が引用符始まりの CTE 値を検査する。
- **教訓**: 袋に入った開け方の指定 — 袋を外す係員は手順を読み、
  袋ごと棚に戻す係員は手順を読まない。

### Security — D1475:

- **問題**: `Content-Description:` の値に `http://`/`https://` 等の
  URL 混入 — 添付説明欄は添付一覧・詳細に出る欄だが、本文 URL
  集めに含めないスキャナの隙間を通る誘導リンク配置。
- **修正**: `has_url_in_content_description` が説明欄中の URL を
  検査する。
- **教訓**: 添付の説明文に書かれた行き先 — 本文の誘導札を見る
  係員の目を通り抜ける別口。

### Security — D1476:

- **問題**: `Resent-*` 欄があるのに必須の `Resent-From:`/
  `Resent-Date:` (または `Resent-Sender:`+`Resent-Date:`) が無い —
  RFC 5322 §3.6.6 の再送ブロック不備。転送履歴の体裁だけ作られ、
  正当転送と手作りが実装間でずれる (Resent-Bcc 残存は D1428)。
- **修正**: `has_incomplete_resent` が Resent 系欄の必須ペア欠落を
  検査する。
- **教訓**: 「転送しました」の札だけあり差出人・日付が無い —
  体裁だけの転送履歴は誰が書いたか分からない。

### Security — D1469:

- **問題**: 添付名が `-` で始まる (`filename="-rf"`、符号化では
  `%2d…` 始まり) — 保存後に `mv`/`cp`/`rm` 等へ引数として渡すと
  オプションに読み替えられ、意図しない動作を誘導する名札偽装。
- **修正**: `has_dash_filename` が filename/name の先頭 `-`
  (RFC 2231 `%2d` 始まりを含む) を検査する。
- **教訓**: 「-」で始まる品名は棚の仕切り記号に読み替わる —
  名札の先頭記号は開け手の作法を変える。

### Security — D1470:

- **問題**: 添付名に `$(`・`${`・バッククォート (符号化では
  `%24`・`%60`) が混入 — 保存名をシェル文字列やスクリプトに
  そのまま埋め込む運用でコマンド置換として展開される。
- **修正**: `has_shell_meta_filename` がシェル式の混入を検査する。
- **教訓**: 名札に書かれた命令文 — 呼び出す側の作法で品名が
  命令に化ける。

### Security — D1471:

- **問題**: `X-Face:`/`Face:`/`X-Image-URL:` — 送信側が自分の
  アイコン画像を同封する旧来欄。表示器が採用すると偽の
  「この人らしい顔」が差出人表示に紛れる (組織内印の自称
  D1389 の視覚版)。
- **修正**: `has_avatar_headers` が送信者指定の顔写真欄を検査する。
- **教訓**: 写真を名乗る欄は誰でも貼れる — 本人の顔の体裁は
  差出人の信用を偽装する入口。

### Security — D1472:

- **問題**: `boundary="a b"` — boundary 値に空白。デリミタ行
  `--a b` を生成する実装と値の途中で切る実装で構造解釈がずれる
  (語尾の `-`/`--` は D1457、70 字超は D1402)。
- **修正**: `has_spaced_boundary` が引用符内の空白入り boundary
  を検査する。
- **教訓**: 区切りに空白の挟まった名札 — 「a まで」を区切りと
  読む係員と「b まで」を区切りと読む係員に分かれる。

### Security — D1465:

- **問題**: `multipart/related` の `type=` が実在するメンバ部品の
  Content-Type を指していない — RFC 2387 のルート部品宣言と
  実体がずれ、最初の部品を採る実装と解決に失敗する実装で
  埋め込みリソースの参照がずれる (start= 欠落は D1426、
  type= 欠落は D1442)。
- **修正**: `has_related_bad_type` が related 器の type= と
  メンバー CT の一致を検査する。
- **教訓**: 「表紙は A 型」と書かれた箱に A 型の部品が無い —
  先頭を表紙と見做す係員と読み直す係員で内容がずれる。

### Security — D1466:

- **問題**: 添付名の拡張子と宣言 Content-Type が意味的に矛盾
  (`invoice.pdf` + `application/x-msdownload`、`evil.exe` +
  `image/png`) — 宣言型でプレビューする実装と拡張子で保存先を
  決める実装で添付の「顔」がずれる名札偽装。
- **修正**: `has_mismatched_attachment_type` がパート単位で
  CT 基底型と name=/filename= 拡張子の矛盾を検査する。
- **教訓**: 「絵です」と名乗る箱に「実行です」と書かれた品が
  入っている — 札と中身の宣言が矛盾する箱は開け方で顔が変わる。

### Security — D1467:

- **問題**: 本文中の `cid:` URL 参照がどのパートの
  `Content-ID:` にも一致しない — 埋め込み解決が失敗し、
  画像を落とす実装と壊れプレースホルダを出す実装で見え方が
  ずれる (Content-ID 重複は D1369、start= 欠落は D1426)。
- **修正**: `has_dangling_cid` が cid: 参照と宣言 Content-ID の
  照合を検査する (`acid:` 等の語尾誤爆を避ける境界検査付き)。
- **教訓**: 「部品番号 X を埋め込め」と書かれても X の部品が
  無ければ、黙って抜く係員と空枠を残す係員に分かれる。

### Security — D1468:

- **問題**: `List-Post:`/`List-Subscribe:`/`List-Help:`/
  `List-Archive:`/`List-Owner:` が `List-Id:` 無しで存在 —
  正規 ML は必ず名札 (List-Id) を持つため、窓口欄だけのメールは
  偽 ML 体裁 (List-Unsubscribe の無 List-Id は D1418)。
- **修正**: `has_orphan_list_headers` が List-Id 欠落下の
  ML 窓口欄を検査する。
- **教訓**: 名札を持たない会が窓口だけ開く — 退会窓口だけでなく
  投稿・購読の窓口も名札が要る。

### Security — D1461:

- **問題**: `In-Reply-To:`/`References:` の値に `<…>` 形の msgid が
  一つも無い — 参照欄の msgid は括弧形が規格で、括弧を欠く裸
  トークンは厳格実装で参照欄ごと捨てられ寛容実装では文字列が残る
  (複数併記は D1443、重複行は D1449、自己参照は D1379)。
- **修正**: `has_bare_msgid_ref` が参照欄値の `<` 欠落を検査する。
- **教訓**: 根札には番号を括る札がある — 裸の数字だけの札は
  読む係員によって参照か落書きか分かれる。

### Security — D1462:

- **問題**: `multipart/signed` で `protocol=` はあるのに
  `micalg=` が無い — 署名のハッシュ方式を特定できず
  「検証不能な署名付き体裁」が残る (protocol 欠落は D1434、
  署名パート欠落は D1378)。
- **修正**: `has_signed_no_micalg` が signed 器の micalg 欠落を
  検査する。
- **教訓**: 封印の方式は名乗るのに判子の形を書かない証書は、
  検証係が押印を再現できない。

### Security — D1463:

- **問題**: `text/plain`/`text/html` の本文部品が
  `Content-Disposition: attachment` と名乗る — CD を尊重する
  表示器では本文が見えなくなり添付としてのみ現れ、
  「表示される本文を持たない」メールになる隠蔽形 (外側 CD は
  D1424、名前無き attachment は D1358)。
- **修正**: `has_attachment_body_part` が text/* 部品の
  attachment 宣言を検査する。
- **教訓**: 「手紙の本文です」と書かれた部品を「添付です」と
  名乗らせると、本文を探す係員の目に本文が消える。

### Security — D1464:

- **問題**: ヘッダ部と本文を分ける空行が文書全体に無い —
  全体がヘッダとして読まれるか、ヘッダ欠落の本文のみと読まれるか
  で構造がまったくずれる (本文冒頭の欄風行は D1386)。
- **修正**: `has_no_body_separator` がヘッダ形行の存在と空行
  欠落の併存を検査する。
- **教訓**: 表紙と中身の間の白ページが無い綴じは、全体を表紙と
  読む係員と中身だけ読む係員に分かれる。

### Security — D1457:

- **問題**: `boundary=x--`・`boundary=a--b` のような `-` で終わる/
  `--` を内包する区切り値 — bchars 上は合法だが開き区切り行が
  `--x--` となり、boundary `x` の閉じ区切りと同一形になるため、
  先頭一致で区切る実装は最初の部品開始を閉じと誤認して全パートを
  捨てる (D1366 非クオート・D1402 長さの姉妹 — 値の「形」の異常)。
- **修正**: `has_dash_boundary` が CT 行の boundary 値の末尾 `-` /
  内部 `--` を検査する。
- **教訓**: 仕切りの名札が「閉じ印」と同じ形をしていると、
  開ける係員が最初から封をされたと読み違える。

### Security — D1458:

- **問題**: `Received: junk` のような、節 (`from`/`by`/`with`/
  `id`/`for`) もコメントも `;` 日付も欠く Received — 実際に
  配送経路を通った痕跡には必ず節か日付があるため、これらを一切
  欠く値は手書きの偽装消印 (Received の有無自体は D1425)。
- **修正**: `has_bad_received` が Received 値を論理行化の上で
  節・コメント・日付の有無を検査する (qmail 系コメント形は
  誤爆しない設計)。
- **教訓**: 消印には必ず押した局と時刻がある — 形だけの丸印は
  自筆の偽装。

### Security — D1459:

- **問題**: 外側ヘッダに `MIME-Version:` が2行以上 — 一意で
  あるべき宣言欄の重複で、先頭を採る実装と末尾を採る実装で
  バージョン解釈がずれる (D1306 系の一意欄重複。値の異常は
  odd_mime_version、パート混入は D1374)。
- **修正**: `has_dup_mime_version` が外側の MIME-Version 行数を
  検査する。
- **教訓**: 「この束の形式」宣言札は一枚 — 二枚あれば読む係員の
  解釈が分かれる。

### Security — D1460:

- **問題**: 外側 `multipart/*` が `boundary=b` を宣言するのに
  本文に `--b` の区切り行が一行も無い — 部品ゼロの空容器で、
  全本文を preamble (表示されない領域) とみなす実装と構造を
  諦めて生本文を見せる実装で見え方がまったくずれる。
- **修正**: `has_unused_boundary` が宣言 boundary の本文使用を
  検査する (区切り自体の異常は D1287/D1366/D1457 が担当)。
- **教訓**: 仕切りの宣言だけして一枚も仕切らない箱は、
  中身を「目次の前書き」と捨てる係員と全部読む係員に分かれる。

### Security — D1453:

- **問題**: `Cookie:`/`Authorization:`/`Proxy-Authorization:`/
  `Origin:`/`Referer:`/`Accept-*:` 等の HTTP **要求**欄 —
  メールに現れるのはプロキシ連結・保存残渣の兆候で、
  Cookie/Authorization の混入は資格情報の漏洩ベクトル
  (D1441 は応答側の制度欄)。`User-Agent:` は正規 MUA の
  欄なので対象外。
- **修正**: `has_http_request_headers` が外側ヘッダの HTTP
  要求欄を検査する。
- **教訓**: 手紙に web の注文票が混ざるとき、最も危ないのは
  資格情報の欄 — 届いた時点で漏れている。

### Security — D1454:

- **問題**: `multipart/alternative` で `text/plain` が
  `text/html` より後に置かれる — RFC 2046 は忠実度の低い順を
  要求するが、逆順の束は「最初の読めるものを採る」実装と
  「最後の読めるものを採る」実装で表示がずれる。
- **修正**: `has_alt_wrong_order` が alternative 器の
  メンバー CT 並びを検査する。
- **教訓**: 同じ内容の束でも並びが逆なら、先頭採用の係員には
  簡易版だけが見えて濃い版が検査を外れる。

### Security — D1455:

- **問題**: `Content-Disposition:` 行に `boundary=` パラメータ —
  boundary は Content-Type の指定で、CD に書くと行頭を見ずに
  `boundary=` を拾う実装が誤って区切りに使い、パート構造を
  書き換える差異工作になる。
- **修正**: `has_cd_boundary` が CD 行の boundary パラメータを
  検査する (CT 行の boundary は正規)。
- **教訓**: 区切りの指定は仕切り板の名札に書くもの —
  処置札に書くと区切りを探す係員が別の場所で裂く。

### Security — D1456:

- **問題**: `From:`/`Sender:`/`Resent-*` の値に `@` を含む
  宛名が一切無い (`From: John Doe` やクオート表示名のみ) —
  名を差出人と読む実装と欄を捨てる実装で読みがずれる
  (片側が空の `a@`/`@b` は D1408、欄欠落は D1432、
  値の空は D1450)。
- **修正**: `has_addrless_from` が差出人欄の値を
  クオート・コメント除去の上で `@` の有無を検査する。
- **教訓**: 名札だけ立って宛名が無い差出人は、読む係員に
  よって「この人」にも「誰でもない」にもなる。

### Security — D1449:

- **問題**: `In-Reply-To:`/`References:` が外側ヘッダに2行以上 —
  RFC 5322 §3.6 では各最大1個。重複する参照欄は先頭を読む実装と
  末尾を読む実装でスレッド帰属がずれる (D1306 の一意欄検査は
  参照欄を対象に含めていなかった)。
- **修正**: `has_dup_thread_headers` が外側ヘッダの参照欄の
  行数を検査する。
- **教訓**: 「どの続きか」を二度名乗ると、読み手ごとに
  別の続きの体裁になる。

### Security — D1450:

- **問題**: `From:`/`To:`/`Subject:`/`Message-ID:` 等の識別欄が
  「欄はあるが値が空」の形 — 欄の欠落 (D1432) とは別に、
  空文字列の値と読む実装と欄ごと無いと読む実装で差出人・
  件名・参照の読みがずれる。
- **修正**: `has_empty_identity_value` が外側ヘッダの識別欄の
  空値を検査する (折りたたみ継続は正規形として除外)。
- **教訓**: 名札はあるのに名が書かれていないと、空の名札と
  無い名札を読み分ける係員の判断が分かれる。

### Security — D1451:

- **問題**: `Content-Type:`/`Content-Disposition:`/`CTE:` 等の
  MIME 欄が「欄はあるが値が空」の形 — `Content-Type:` の空値は
  既定 `text/plain` を当てる実装と壊れたヘッダとして捨てる
  実装で型・添付判定がずれる (欠落は `missing_content_type`)。
- **修正**: `has_empty_mime_value` が外側+パート全ヘッダ run の
  MIME 欄の空値を検査する。
- **教訓**: 種類の札だけ立って中身の指定が無いと、既定値を
  補う係員と壊れ札として捨てる係員で別の物になる。

### Security — D1452:

- **問題**: `Content-Type` の `charset=`/`charset=""` が空値 —
  既定 charset を適用する実装と空文字を符号化名として扱う実装で
  本文の文字解釈がずれる。
- **修正**: `has_empty_charset` が CT 行の charset パラメータの
  空値を検査する (危険 charset は D1301、宣言と本文の不一致は
  D1329 が担当)。
- **教訓**: 「言語は」とだけ書かれた指定は、読み手に既定か
  無名かを選ばせる放置の形である。

### Security — D1445:

- **問題**: `X-Priority:`/`Priority:`/`Importance:`/
  `X-MSMail-Priority:` の値が既定集合を外れる — `9`・`banana`・
  空値は規定に依らない手書き生成の形跡で、強弱を読む実装と
  捨てる実装で急かせ具合がずれる (D1340/D1431 の値異常版)。
- **修正**: `has_bad_priority_value` が外側ヘッダの緊急度欄の
  値を既定集合と照合する。
- **教訓**: 体裁を名乗る欄の値が辞典に無いとき、書き手は
  規格ではなく手で書いたものである。

### Security — D1446:

- **問題**: `From:`/`Sender:`/`Resent-From:`/`Resent-Sender:`/
  `Return-Path:` の値にグループ構文 `label: members;` が
  現れる — mailbox 欄に許されない address 構文で、許容実装は
  先頭メンバを差出人に、厳格実装は欄ごと捨てる (D1363 は宛先
  欄の空グループ)。
- **修正**: `has_mailbox_group` が mailbox 欄の値を
  クオート・コメント・ドメインリテラル除去の上で
  `:` … `;` の並びを検査する。
- **教訓**: 一人だけが記す欄に名簿の書式を混ぜると、
  誰を名指すか読み手ごとに違う人になる。

### Security — D1447:

- **問題**: 外側ヘッダ run に `:` を持たない非空行が混入 —
  `名前:値` の形でも継続行でもない壊れ行は、ヘッダ打ち切り・
  読み飛ばし・継続扱いのどれになるかが実装間でずれ、
  以降の欄の読みが全部ずれる。
- **修正**: `has_headerless_line` が外側ヘッダの物理行の
  `:` 有無を検査する (行頭 `From ` の mbox 区切りは別検出)。
- **教訓**: 書式を外れた行が紛れると、その行だけでなく
  後続の全行の読み方が読み手で変わる。

### Security — D1448:

- **問題**: ヘッダ名 (`:` の前) に印刷可能 ASCII 以外の文字 —
  制御文字・空白・非 ASCII が混じると厳格実装は欄ごと拒否、
  寛容実装は読み込むため欄の有無がずれる
  (名前末尾空白は `spaced_header_name` が担当、こちらは
  名前本体の文字種)。
- **修正**: `has_bad_header_name` が外側ヘッダ各行の名前部の
  バイト種を検査する。
- **教訓**: 名札に使えない文字を混ぜると、読む人によって
  その欄は存在したり消えたりする。

### Security — D1441:

- **問題**: `Set-Cookie:`/`Location:`/`Refresh:`/`ETag:`/
  `X-Frame-Options:`/`Content-Security-Policy:` 等の HTTP 応答
  制度欄 — メールに現れるのはプロキシ連結・ページ保存残渣・
  内容側の誘導 (Location/Refresh はリダイレクト命令) の兆候
  (D1344 のフレーミング欄とは別群)。
- **修正**: `has_http_response_marks` が外側ヘッダの HTTP
  応答欄を検査する。
- **教訓**: 別の制度の記録が届くとき、経路の連結ミスか
  内容側がその制度を演じているかのどちらかである。

### Security — D1442:

- **問題**: `multipart/related` に `type=` 指定が無い — RFC 2387
  の必須欄を欠くと関連リソースの親 (ルート部品) の型が特定
  できず、start= で探す実装と先頭パートを使う実装で表示が
  ずれる (D1426 の指し手欠落と別の型欠落)。
- **修正**: `has_related_no_type` が `multipart/related` の
  CT 行の `type=` 有無を全パートで検査する。
- **教訓**: 関連の器は「どの型の部品が親か」の明記がないと
  各読み手が勝手に親を選ぶ。

### Security — D1443:

- **問題**: `In-Reply-To:` が複数の msgid (`<a@b> <c@d>`) を
  併記 — 単一返信先の欄に複数を並べる形は複数スレッドを
  束ねる「統合の体裁」の偽造で、先頭を読む実装と末尾を読む
  実装でスレッド帰属がずれる。
- **修正**: `has_multi_inreply` が In-Reply-To 値内の
  msgid `<…>` の数を検査する (References の複数併記は正規)。
- **教訓**: 「一つだけ指す欄」に二つ指させる併記は、
  読み手に帰属の選ばせ合いをさせる工作である。

### Security — D1444:

- **問題**: 添付名 (`filename=`/`name=`) が `.` または空白で
  終わる — Windows は名末の `.`・空白を保存時に剥がすため
  `evil.exe.` が `evil.exe` として落ち、宣言名と保存名がずれる。
- **修正**: `has_filename_trailing` が CT/CD 行の添付名値の
  末尾 `.`/空白を検査する (トークン境界外の `xfilename=` は
  対象外)。
- **教訓**: 名札の名と保存される名がずれると、見せた種類と
  実際に落ちた種類が違うものになる。

### Security — D1437:

- **問題**: `Subject:` が encoded-word (`=?utf-8?B?UmU6?=` 等) で
  先頭から `re:` に復号されるのに `In-Reply-To:`/`References:` が
  無い — 生読みで `re:` を検査する偽返信検出 (D1361) を、
  復号して初めて返信の体裁になる符号化で回避する形。
- **修正**: `has_encoded_re_subject` が Subject 先頭の連続
  encoded-word を Q/B 復号し、復号形が `re:` で始まるのに
  参照欄を欠く形を検査する (Fwd/Fw 系は転送のため対象外)。
- **教訓**: 体裁の検査は生の字句と復号後の両方で行う —
  復号して初めて現れる体裁は生読みの檻を素通りする。

### Security — D1438:

- **問題**: `multipart/report` に `report-type=` 指定が無い —
  RFC 6522 の必須欄を欠くと「何の報告か」(delivery-status/
  disposition-notification 等) が特定できず、DSN/MDN として
  処理する実装と通常 multipart でずれる (D1434 の報告器版)。
- **修正**: `has_missing_report_type` が `multipart/report` の
  CT 行の `report-type=` 有無を検査する。
- **教訓**: 報告の器は「何の報告か」の明記が検査の前提 —
  種別不明記の器は機械仕分けの網をすり抜ける。

### Security — D1439:

- **問題**: 裸の `Charset:`/`Encoding:` 欄 — RFC 2978/1154 で
  廃止済みのメッセージ全体宣言。尊重する実装は宣言に従って
  復号し、無視する実装は本文を生読みするため読みがずれる。
- **修正**: `has_obsolete_decl_headers` が外側ヘッダの
  `charset:`/`encoding:` 行を検査する (CT パラメータの
  `charset=` は対象外)。
- **教訓**: 廃止された宣言経路は「正」の経路と読みを争わせる
  — 欄として独立した旧式宣言は残存そのものがずれの種。

### Security — D1440:

- **問題**: 非 message/* MIME パートのヘッダ run に `From:`/
  `Subject:`/`Date:` 等のメッセージ級欄が混在する — パート
  属性として採用する実装と飾りとして無視する実装で読みが
  ずれる (D1386 本文第2表紙のパート版)。
- **修正**: `has_part_field_headers` が宣言 boundary に沿って
  パートヘッダ run を追跡し、run 内のメッセージ級欄を検査する。
- **教訓**: 部品の札は部品のことだけ書くべき — 手紙の表紙が
  部品の中に紛れ込むと、読み手によって「内側の別の手紙」に
  見える。

### Security — D1433:

- **問題**: `Authentication-Results:`/`Received-SPF:` 欄が
  `dkim=pass` を記すのに `DKIM-Signature:` 欄が無い — 検証を
  経ずに「検証済み」の体裁だけ書き込んだ自称印で、認証結果を
  表示に採用する実装では差出人検証の偽装になる。
- **修正**: `has_inconsistent_auth_results` が署名欄不在と
  `dkim=pass`/`domainkeys=pass` 判定の矛盾を検査する。
- **教訓**: 「検証済み」の印は検証対象が在って初めて意味を
  持つ — 対象の不在と結果の両方を見る。

### Security — D1434:

- **問題**: `multipart/signed`/`multipart/encrypted` に
  `protocol=` 指定が無い — RFC 3156/1847 の必須欄を欠くと
  署名・暗号化の方式が特定できない器になる (D1378 は署名
  パート欠落側を担当)。
- **修正**: `has_missing_crypto_protocol` が両型の CT 行の
  `protocol=` 有無を全パートのヘッダ run で検査する。
- **教訓**: 封印の器は「何式の封印か」まで書かれて初めて
  検証に載る — 方式不明記の器は体裁だけの器。

### Security — D1435:

- **問題**: `Thread-Index:`/`Thread-Topic:`/`X-Thread-*` が
  `In-Reply-To:`/`References:` 無しで存在する — Outlook 系の
  スレッド管理欄だけで「既存スレッドの続き」の体裁を作る
  偽スレッド工作 (D1361 `Re:` の Outlook 形対応物)。
- **修正**: `has_orphan_thread` が thread 印の有無と参照欄の
  有無の不一致を検査する。
- **教訓**: 「続き」を名乗る札は参照できる親を指さないと
  体裁の貼り紙にすぎない。

### Security — D1436:

- **問題**: アドレス欄の addr-spec に `%` (sendmail %-hack) や
  `!` (UUCP bang path) の経路指定構文 — 解釈する実装は中継先を
  書き換え、しない実装は文字通りに読み、宛名がずれる。
- **修正**: `has_routing_addr` がアドレス欄のクオート・
  コメント外の @ トークン内 %/! を検査する。
- **教訓**: 宛名の中の経路構文は「誰」を「どこ経由で」に
  読み替える — 制度が変わると読みも変わる。

### Security — D1429:

- **問題**: `Content-Type:` の `boundary*=`/`boundary*0=` (RFC 2231
  拡張属性記法) — 記法を解釈する実装は復号した区切りで分割し、
  解釈しない実装は boundary 自体を見失い構造全体の解釈がずれる。
- **修正**: `has_star_boundary` が CT 論理行の `boundary*` 形
  パラメータを検出する (`xboundary` 等の内側一致は除外)。
- **教訓**: 区切り名にまで別記法が届くと、境界を引ける実装と
  引けない実装で構造が根本からずれる。

### Security — D1430:

- **問題**: 添付名 (`filename=`/`name=`) が `://` を含む URL の
  形 — リンクとして描く実装と保存名として扱う実装で添付の
  顔がずれる (誘導先を名札に潜ませる形)。
- **修正**: `has_url_filename` が CT/CD 行の添付名値の `://`
  含有を検査する (本文中の URL は対象外)。
- **教訓**: 名札が URL の顔を持つと、それは保存する名ではなく
  踏ませる罠の入口になり得る。

### Security — D1431:

- **問題**: `X-Priority: 1` と `Importance: low` のような
  「急げ」と「不急」の併記 — 優先度表示が実装間でずれる
  圧力欄の矛盾 (D1340 の矛盾版)。
- **修正**: `has_conflicting_priority` が X-Priority/Priority/
  Importance の値を高低に分けて両立を検査する。
- **教訓**: 圧力の体裁は一方向だけでなく、矛盾した併記その
  ものが作られた形跡になる。

### Security — D1432:

- **問題**: 外側ヘッダに `From:` (Resent-From 含む) が1行も無い
  — RFC 5322 の必須欄を欠き、`Sender:` を採用する実装と空欄を
  見せる実装で差出人の読みがずれる (D1334 の欄欠落版)。
- **修正**: `has_no_from` が外側ヘッダ論理行の `from:`/
  `resent-from:` 有無を検査する。
- **教訓**: 必須欄の欠落は「誰から」を実装の裁量に委ねる
  — 宛名の無い手紙は名乗り方が読み手次第になる。

### Security — D1425:

- **問題**: 外側ヘッダに `Received:` が1行も無い — 配送経路の各
  MTA が追記する通過記録の皆無は、配送を経ていない手作り生成品
  (ローカル注入・スプーフィング材料) の兆候。
- **修正**: `has_no_received` が外側ヘッダ部の `received:` 行の
  有無を検査する (本文中の同名文字列は対象外)。
- **教訓**: 通過記録の「無いこと」自体が形跡 — 記録が無い
  メールはどこからも来ていない。

### Security — D1426:

- **問題**: `multipart/related` の `start=<cid>` が参照する
  Content-ID を持つパートが無い — 先頭パートを選ぶ実装と
  表示不能に陥る実装でルート部品の見え方がずれる。
- **修正**: `has_dangling_start` が `start=` 値と宣言済み
  Content-ID を突き合わせる (`xstart=` 等の内側一致は除外)。
- **教訓**: 指し手の届かない根指定は、何を見せるかが読み手で
  分かれる。

### Security — D1427:

- **問題**: `List-Id:` の値が `<label.host>` の形でない (山括弧・
  ドット欠落) — 厳格実装ではリストを識別できず、形の崩れた
  識別子は手作り生成品の兆候 (D1418 の形状版)。
- **修正**: `has_malformed_listid` が `List-Id:` の `<…>` と
  内部ドットを検査する。
- **教訓**: 識別子の形が崩れていると、読み手ごとに「どれが
  識別子か」がずれる。

### Security — D1428:

- **問題**: `Resent-Bcc:` — 再送ブロックの Bcc は配送時に
  除去されるべき受取人欄であり、届いたメールに残ること自体が
  経路異常。隠し宛先の露出でもある (D1331 Bcc 残存の再送版)。
- **修正**: `has_resent_bcc` が外側ヘッダの `resent-bcc:` を
  検出する。
- **教訓**: 隠し宛先の欄は「再送」の表紙にも同じ漏洩形を
  持つ。

### Security — D1421:

- **問題**: 本文中の単独 `.` 行は SMTP DATA 終端の形 — 終端として
  切り捨てるパーサと本文として表示する実装で、ドット以降の
  内容の見え方がずれる (終端以降への潜伏)。
- **修正**: `has_smtp_dot_line` が本文行の孤立ドットを検出する。
- **教訓**: 本文に配送プロトコルの終端記号が混ざると、
  どこまでが本文かが実装間でずれる。

### Security — D1422:

- **問題**: 本文途中の `From user@host ... 年` 行は mbox 区切りの
  形 — mbox として格納する実装では以降が別メッセージになり
  隠れた第2メッセージが生まれる格納差異 (D1308 の先頭版に対し
  本文側)。
- **修正**: `has_midbody_mbox_from` が本文行の `From `+`@`+4桁年
  の組み合わせを検出する (通常の From 文は対象外)。
- **教訓**: 格納形式の区切りが本文に潜ると、一通の中に
  二通目が潜む。

### Security — D1423:

- **問題**: `Reply-To:` に複数アドレスがあると返信が見えない
  宛先へ分流される — 単一返信先を想定する実装と全宛先へ送る
  実装で届き方がずれる (BEC の返信横取りの素地)。
- **修正**: `has_multi_reply_to` が Reply-To 論理行のコメント・
  引用を除いた `@` の個数とカンマを検査する。
- **教訓**: 返信先の欄は「一か所」を前提にする読み手が多い —
  二枚目の宛名は分流の素地。

### Security — D1424:

- **問題**: 外側ヘッダに `Content-Disposition:` — CD はパートの
  扱い欄でメッセージ全体には意味を持たない。メール全体を添付
  として扱う実装と無視する実装で扱いがずれる (HTTP 由来の欄の
  メール表紙への混入)。
- **修正**: `has_outer_content_disposition` が外側ヘッダ部のみの
  CD 行を検出する (パート側 CD は対象外)。
- **教訓**: パートの欄が表紙に貼られると「このメール自体が
  添付か」の読み分かれが生まれる。

### Security — D1417:

- **問題**: `Content-Type:` のメディア型がクオートされている
  (`"text/plain"`) と、引用符を剥がす実装とそのまま拒否する
  実装で型解釈がずれる — 規格上メディア型は token であり
  quoted-string は許されない。
- **修正**: `has_quoted_media_type` が外側ヘッダの CT 論理行で
  値先頭の引用符を検出する (パラメータ値のクオートは対象外)。
- **教訓**: トークンであるべき場所の引用符は、剥がす側と
  拒否する側の読み分かれを生む。

### Security — D1418:

- **問題**: `List-Unsubscribe:`/`List-Post:`/`List-Subscribe:` 等の
  便益欄があるのに `List-Id:` を欠く — 「配信リストからの退会」の
  体裁だけを作る偽の unsubscribe 誘導 (識別子なき退会は名乗りも
  無い罠)。
- **修正**: `has_list_unsub_without_id` が外側ヘッダの List-* 系
  便益欄と `List-Id:` の有無を突き合わせる。
- **教訓**: 便益の体裁は識別子との対で成り立つ — 片方だけの
  自称を突く。

### Security — D1419:

- **問題**: 添付名 (`filename=`/`name=`/`filename*=`/`name*=`) が
  255 バイトを超える — 切り詰める実装と拒否する実装で保存名が
  ずれ、末尾の拡張子が落ちて「見せた名前」と「保存される名」が
  食い違う偽装材料になる。
- **修正**: `has_long_filename` が CT/CD 行の添付名値の長さを
  検査する (他欄の長い値は対象外)。
- **教訓**: 名札の長さ上限超過は切り詰め側と拒否側で名がずれる
  — 見えた名がそのまま保存されるとは限らない。

### Security — D1420:

- **問題**: `Content-Type:`/`Content-Disposition:` のパラメータ
  区切りで名前が空 (`;=`/`; =`) の形 — 読み飛ばす実装とエラーに
  する実装で以降の boundary/filename 解釈がずれる。
- **修正**: `has_empty_param_name` が CT/CD 論理行の `;` 直後の
  `=` を検出する。
- **教訓**: 区切り記号の後の空白名は、パラメータ列の歩みを
  実装間でずらせる。

### Security — D1413:

- **問題**: `Sensitivity:` 欄 (company-confidential/personal/private)
  は送信側が内容に貼る機密度の名札 — 表示する実装では「機密案件」
  の体裁を作る圧力欄 (BEC の「内密の件」演出と同型)。
- **修正**: `has_sensitivity_claim` が外側ヘッダの `sensitivity:`/
  `x-sensitivity:`/`sensitivity-level:` を検出する。
- **教訓**: 圧力の体裁は緊急度 (X-Priority, D1340) だけでなく
  機密度の名札でも作られる。

### Security — D1414:

- **問題**: `Message-ID:`/`Resent-Message-ID:` に `<…>` が2個以上
  あると、先頭/末尾採用で識別子がずれる (スレッド偽装の素地)。
- **修正**: `has_double_msgid` が msgid 欄の値中の `<` の個数を
  検査する (In-Reply-To/References の複数 msgid は正当なので
  対象外)。
- **教訓**: 一意欄は値の中でも一意であるべき — 欄の個数だけで
  なく値内部の構造も重複の形になる。

### Security — D1415:

- **問題**: `From:`/`Sender:`/`Return-Path:` のローカル部が
  `mailer-daemon`/`postmaster`/`hostmaster` — 配送器の役割名を
  名乗るメールは偽の配送失敗通知の形 (「戻ってきた添付を開かせる」
  malspam の定番)。
- **修正**: `has_system_addr_from` が差出人系欄の addr-spec トークンの
  ローカル部を検査する (完全一致で誤爆しない)。
- **教訓**: 役割名の名乘りは配送失敗の体裁を作る素地 —
  人間が差出人に使わない名を切り分ける。

### Security — D1416:

- **問題**: `Apparently-From:`/`X-Apparently-From:`/
  `Apparently-Sender:` 等の差出人側「見せかけ」欄 — 宛先側の
  `X-Apparently-To:` は既存印群が担当するが差出人側は未対象。
- **修正**: `has_apparently_from` が外側ヘッダの差出人側
  Apparently-* 欄を検出する。
- **教訓**: 「見せかけ」の欄は宛先側だけでなく差出人側にもある
  — 対になる欄は対に塞ぐ。

### Security — D1409:

- **問題**: multipart メールの preamble (最初の boundary 行より前)
  に空行以外の内容があると、規格上は表示されない領域だが生
  テキストを走査する検査には読まれる — 規格上見えない場所への
  注記・ペイロード潜伏経路。
- **修正**: `has_preamble_content` が外側 multipart 宣言のある
  メールで、宣言 boundary で始まる行より前の非空行を検出する。
- **教訓**: 構造の前後 (preamble/epilogue) は「規格が読まない
  領域」— 規格順守の表示器と生テキスト検査で可視性が割れる。

### Security — D1410:

- **問題**: 閉じ boundary `--b--` 以降の epilogue も規格上は
  切り捨てられる領域 — 末尾まで走査する検査には内容が見える
  ため閉じ境界の向こうにペイロードを隠せる (Outlook 系で実績)。
- **修正**: `has_epilogue_content` が外側ヘッダ宣言の boundary の
  閉じ行を厳密一致で見つけ、以降の非空行を検出する (入れ子の
  内側境界は外側宣言に無いため誤判定しない)。
- **教訓**: 「終わった構造の後」は表示器が読まない死角 —
  検査器がそこを読むなら潜伏場所になる。

### Security — D1411:

- **問題**: `application/pdf; charset=utf-8` 等、非 `text/*`/
  `message/*` 型への `charset=` パラメータは無視する実装と適用
  を試みる実装で解釈がずれる型と引数の組み合わせ異常。
- **修正**: `has_nontext_charset` が論理行化した CT 欄で主型が
  text/message 以外なのに charset= を持つ形を検出する。
- **教訓**: 引数の妥当性は型ごとに決まる — 組み合わせの異常も
  独立した検査面になる。

### Security — D1412:

- **問題**: `Newsgroups:`/`Followup-To:`/`Path:`/`Xref:`/
  `NNTP-Posting-Host:`/`NNTP-Posting-Date:` 等の Usenet 経路欄は
  メールに存在しない制度の欄 — 連結ゲートウェイ経由・フォージの
  兆候 ( `Control:`/`Supersedes:`/`Approved:` は D1364 が担当)。
- **修正**: `has_nntp_routing` が外側ヘッダの NNTP 経路欄を
  検出する (`Organization:`/`Distribution:` は RFC 2076 でメールに
  も認められるため対象外)。
- **教訓**: 制度の混在は欄ごとに検査が必要 — 制御欄だけでは
  なく配送・分類欄も別制度の痕跡。

### Security — D1405:

- **問題**: `Content-Transfer-Encoding:` の値が単一トークンでない
  ( `base64; x`・`base64 extra`・空値 ) と、先頭トークンだけ読む
  実装と全体を未知値として扱う実装で符号化の解釈がずれ、本文
  復号の有無がパーサ間で分かれる。
- **修正**: `has_junk_cte_value` が CTE 値が単一のクリーンな
  トークン (英数字 + `-`/`_`、空白・`;`・`,` なし) でないことを
  検出する。論理行化で折りたたみも評価。
- **教訓**: 値が「トークン」であるべき欄は、値自体の形を検査
  しないと寛容実装との差異でペイロードが見えなくなる。

### Security — D1406:

- **問題**: `Deliver-To:`/`Deliver-Date:`/`X-Deliver-To:`/
  `X-Delivery:` 等の配送到着記録欄は、配送器が到着時に付ける
  記録であり、送信側が書き込むと「配送済み」の体裁を自称する
  ( `Delivered-To`/`X-Envelope-To` 系統は既存印群が担当、裸欄は
  未対象だった)。
- **修正**: `has_deliver_to_mark` が外側ヘッダ部の裸 `Deliver-To`/
  `Deliver-Date`/`X-Deliver-To`/`X-Delivery` を検出する。
- **教訓**: 記録欄は「付ける側がいつ付けるか」が規格の前提 —
  送信側から届く到着記録は全て自称とみなす。

### Security — D1407:

- **問題**: `Message-ID:`/`In-Reply-To:`/`References:` の msgid の
  ドメイン部が `[…]` リテラル (`<id@[127.0.0.1]>`) は、通常の
  MUA が生成する識別子に見られない形で手作り生成品の兆候。
- **修正**: `has_literal_msgid_domain` が msgid 欄の値中の `@`
  直後が `[` で始まる形を検出する (折りたたみ対応)。
- **教訓**: 識別子のドメインも名指しの対象 — リテラルドメインの
  自称は差出人欄 (D1370) だけでなく識別子欄にも現れる。

### Security — D1408:

- **問題**: `From: a@`・`From: @b`・`To: a@@b` のようなローカル部
  またはドメイン部が空のアドレスは、抽出する実装と拒否する実装で
  表示される宛名がずれる (D1353 は atom 違反のみ担当し、空側は
  未対象だった)。
- **修正**: `has_empty_addr_side` がアドレス欄のクオート/コメント
  外の `@` を走査し、片側の atom が空または `@@` 連続を検出する。
  `"a@b"@x` (クオート局所部の正当形) は `@` の直前が閉じクオート
  なので不発火。
- **教訓**: atom 違反の検査と別に「atom そのものの欠落」も形の
  異常 — 空は違反よりも弱い形で検査を素通りする。

### Security — D1401: 外側 Content-Type/Content-Disposition/CTE の重複が未検査

- **問題**: D1306 は subject/from/date 等の一意欄を対象だが、外側の MIME 構造欄 (CT/CD/CTE) の重複は未対象 — 先頭/末尾採用でメディア型・添付判定・符号化が実装間でずれる。
- **修正**: `has_dup_mime_headers` — 外側ヘッダで3欄の出現回数を検査 → `Envelope.dup_mime_headers` → render_risks 警告。
- **教訓**: 小包の「種類」欄に二度記入された伝票 — どちらが本物かは係員次第。

### Security — D1402: boundary パラメータの 70 文字超過が未検査

- **問題**: RFC 2046 の boundary 上限は 70 文字 — 超過値は先頭70文字に切り詰める実装と全文を読む実装で区切り解釈がずれ、前半だけが実区切りとして機能する偽装構造になり得る。
- **修正**: `has_long_boundary` — boundary= 値の長さを検査 (クオート有無両対応) → `Envelope.long_boundary` → render_risks 警告。
- **教訓**: 規格の票がはみ出す見出し線 — 読めるのは枠に収まる部分だけ。

### Security — D1403: 表示名中の URL 文字列が未検査

- **問題**: `From: "http://click.evil" <a@b>` の表示名中の URL は、表示名をリンク化する実装でクリック可能な誘導経路になる (D1335 はアドレス形の表示名のみ対象)。
- **修正**: `has_url_display_name` — クオート内表示名に `http://`/`https://`/`hxxp`/`www.` かつ後続 `<addr>` を検出 → `Envelope.url_display_name` → render_risks 警告。
- **教訓**: 名札の面に URL を刷った名刺 — 名前をタップすると別の場所に連れて行かれる。

### Security — D1404: アドレスドメインのアンダースコア混入が未検査

- **問題**: `user@my_host.example` の `_` はメールアドレスのドメインとして非合法 — 拒否する実装と受理する実装で名指し照合・評価がずれる (dot-atom 違反は D1353、非 ASCII は D1359 が担当)。
- **修正**: `has_underscore_domain` — コメント・クオートを除いたアドレスのドメイン部に `_` を検出 → `Envelope.underscore_domain` → render_risks 警告。
- **教訓**: 住所に載らない区画記号で書かれた宛名 — 地図によって行き先が変わる。

### Security — D1397: 配送失敗通知先 (Errors-To/Return-Error-To) の送信側指定が未検査

- **問題**: `Errors-To:`/`Return-Error-To:`/`Deliver-Errors-To:` は不達通知の転送先を送信側が書く旧来の欄 — 届いたメールに付いていると「失敗する宛先を試す偵察」の応答経路を内蔵させる。`X-Errors-To` 系は既存のバウンス印群が担当するが裸欄は未対象だった。
- **修正**: `has_bounce_directive` — 外側ヘッダで3欄を検出 → `Envelope.bounce_directive` → render_risks 警告。
- **教訓**: 差出人が勝手に書き込んだ「届かなければこちらへ転送」の案内。

### Security — D1398: 同一パート run 内の CT/CD/CTE/Content-ID 重複が未検査

- **問題**: 外側の一意欄重複 (D1306) と同じく、同一パートのヘッダ run で同名欄が二度現れると先頭/末尾採用で型・添付判定・符号化が実装間でずれる。
- **修正**: `has_part_header_dup` — 宣言 boundary でパート run を追跡し run ごとに集合をリセットして重複を検出 → `Envelope.part_header_dup` → render_risks 警告。
- **教訓**: 一つの箱に二枚貼られた内容物ラベル — どちらを信じるかは受取人次第。

### Security — D1399: charset 宣言のない text/* + 高位バイト本文が未検査

- **問題**: charset 無しの既定は us-ascii — 高位バイトがあると「UTF-8 と推す」「windows-1252 と推す」「拒否」で本文の見え方がずれる。宣言ありの不一致は D1329 が担当するが、宣言自体の欠落は対象外だった。
- **修正**: `has_missing_charset_hibit` — text/* で charset= 欠落かつ本文に高位バイトを検出 (外側 + パート両走査) → `Envelope.missing_charset_hibit` → render_risks 警告。
- **教訓**: 言語を明記せずに書かれた手紙 — 読み手が勝手に言語を選ぶ。

### Security — D1400: 旧式 `Encrypted:`/`Decryptable:` 欄の自称が未検査

- **問題**: RFC 822 時代の `Encrypted:` 欄は現行では意味を持たない — 存在は「暗号化済み」の体裁を値だけで語る自称 (PEM 構造は D1387、PGP/S-MIME 内包は D1349 が担当)。
- **修正**: `has_legacy_encrypted_header` — 外側ヘッダで2欄を検出 → `Envelope.legacy_encrypted_header` → render_risks 警告。
- **教訓**: 「暗号で封印済」とだけ書かれた封筒 — 中は透けて見える。

### Security — D1393: 添付名の Windows 非合法文字 (* ? | < >) が未検査

- **問題**: `filename="a?b.exe"` のような Windows 保存不能文字を含む添付名は、拒否する実装と別名保存する実装で宣言名と保存名がずれる — 名指し検査をサニタイズ差異が素通りする。
- **修正**: `has_invalid_filename_chars` — filename/name 値の `*?|<>` を検出 → `Envelope.invalid_filename_chars` → render_risks 警告。
- **教訓**: 届け先の町で使えない文字で書かれた宛名 — 配達先で書き換えられる名前。

### Security — D1394: RFC 2231 連番パラメータの欠番が未検査

- **問題**: `filename*0=a; filename*2=c` (*1 欠番) は、欠番以降を連結しない実装と番号順に全連結する実装で添付名がずれる — 0 始まり連続が前提の連番の形の崩れ。
- **修正**: `has_rfc2231_gap` — filename/name 系統ごとに連番番号を集め、0..=max の連続性を検査 → `Envelope.rfc2231_gap` → render_risks 警告。
- **教訓**: 綴じ番号が抜けた分冊百科 — 欠けた巻をどう数えるかは読み手次第。

### Security — D1395: パート Content-ID の角括弧欠落が未検査

- **問題**: `Content-ID: abc123` (<> 無し) は厳格実装で cid: 参照が解決できず画像が表示されない一方、寛容実装は裸の値で照合し表示する — 参照可能性が実装間でずれる。
- **修正**: `has_unbracketed_content_id` — パートヘッダの `content-id:` 値が `<` で始まらないか検査 → `Envelope.unbracketed_content_id` → render_risks 警告。
- **教訓**: 額縁に入っていない図版番号 — 本文中の「図1を見よ」が指し先を失う。

### Security — D1396: 符号化添付名の制御文字パーセント符号化が未検査

- **問題**: `filename*=utf-8''a%0ab.exe` は復号で改行を含む名になり、表示を2行に割る実装としない実装で添付名の見え方がずれる — 偽拡張子を改行の向こうに隠す材料。
- **修正**: `has_encoded_control_filename` — `filename*`/`name*` 値の `%00`–`%1f`/`%7f` を検出 → `Envelope.encoded_control_filename` → render_risks 警告。
- **教訓**: 名札の裏に折り込まれた第二の名前 — 開いたときだけ現れる。
l notable changes to Kaname are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security — D1389: Exchange 組織内記録ヘッダの自称が未検査

- **問題**: `X-MS-Exchange-Organization-AuthAs: Internal`/`-MessageDirectionality:`/`X-MS-Exchange-CrossTenant-*`/`SafeLinks-*`/`X-MS-PublicTrafficType:` は受信側で付与される組織内輸送記録 — 送信側が書き込むと「社内からの発信」の体裁が偽造できる (AuthAs: Internal は BEC の定番)。
- **修正**: `has_exchange_org_claim` — ms_eop_marks の補集合 (organization-/crosstenant/atpmessageproperties/safelinks/skg-/office365-filtering/publictraffictype/traffictypediagnostic/oob-tlc) を検出 → `Envelope.exchange_org_claim` → render_risks 警告。
- **教訓**: 受付で捺されるはずの構内通行印を来客が自署した通行証。

### Security — D1390: 配送記録ヘッダ (Return-Path/Delivered-To) の重複が未検査

- **問題**: Return-Path は最終配送 MTA が1度だけ付け、Delivered-To も配送ごとに1行 — 2回現れるのは再注入ループや配送系統重複の残渣で単発メールにはあり得ない形 (D1271 は空欄側のみ対象)。
- **修正**: `has_dup_delivery_headers` — 外側ヘッダで2欄の出現回数を数える → `Envelope.dup_delivery_headers` → render_risks 警告。
- **教訓**: 二度捺された配達証印 — 通ったはずのない二つの窓口の記録。

### Security — D1391: 添付名のドット・空白始まり (隠れ名) が未検査

- **問題**: `filename=".evil.exe"` は Finder/Unix 一覧で不可視の dotfile、`filename=" report.pdf"` は先頭空白で見え方がずれる — 保存されるが一覧に現れない添付。`filename*=` の `%2e` 先頭も同型。
- **修正**: `has_hidden_filename` — filename/name パラメータ値の先頭文字を検査 → `Envelope.hidden_filename` → render_risks 警告。
- **教訓**: 名札が透明インクで書かれた添付 — 棚に載るが目録に出ない。

### Security — D1392: CT/CD パラメータのクオート不対応が未検査

- **問題**: `filename="a` のような未終端クオートは、行末まで値として読む実装と `;` で切る実装で添付名がずれる — パラメータ境界の解釈差異。
- **修正**: `has_unbalanced_param_quote` — CT/CD 論理行をスキャン、コメント内 `"` と `\"` を除いて不対応を検出 → `Envelope.unbalanced_param_quote` → render_risks 警告。
- **教訓**: 閉じられない引用符 — 「ここまでが名前だ」の線が引けない書類。

### Security — D1385: ヘッダ run 先頭の孤児継続行 (WSP 始まり) が未検査

- **問題**: 外側ヘッダ・パートヘッダ run の**先頭行**が空白/タブ始まりだと、親を持たない孤児折りたたみになる — 先頭行を捨てる実装とヘッダ名として読む実装で最初の欄の解釈がずれる。
- **修正**: `has_leading_continuation` — 宣言 boundary 追跡で各 run の先頭行を検査 → `Envelope.leading_continuation` → render_risks 警告。
- **教訓**: 上の行を持たない続き行 — 行頭が下がっただけの書類。

### Security — D1386: 本文冒頭のヘッダ形連続行が未検査

- **問題**: 外側ヘッダ終端の空行直後に `Name:` 形の行が連続すると、「本文文字列」と読む実装と「後続ヘッダブロック」と読む実装 (formail 系・.eml 再取り込み・mbox 格納) で欄解釈がずれる。
- **修正**: `has_body_header_block` — 本文冒頭の `Name:` 形連続 (2行以上) を検出 → `Envelope.body_header_block` → render_risks 警告。
- **教訓**: 本文の顔をした第二の表紙 — 格納差異で隠れ欄が復活する。

### Security — D1387: RFC 1421 PEM ヘッダ (Proc-Type 等) が未検査

- **問題**: `Proc-Type:`/`DEK-Info:`/`Content-Domain:`/`MIC-Info:`/`Key-Info:`/`Originator-ID-*`/`Recipient-ID-*`/`Issuer-Certificate:`/`Issuer:` は廃止済み Privacy Enhanced Mail の印 — この形式で保護された内容は現行スキャナが「暗号化メール」として扱わず (D1349 は PGP/S-MIME のみ対象)、走査が素通りする死角。
- **修正**: `has_pem_markers` — ヘッダ部で PEM 系欄を検出 → `Envelope.pem_markers` → render_risks 警告。
- **教訓**: 誰も読めなくなった旧規格の封印 — 検査不能を通知する。

### Security — D1388: 下書き・エクスポート残渣ヘッダ (X-Unsent 等) が未検査

- **問題**: `X-Unsent: 1` (Outlook/PST の未送信下書き印)/`X-Original-ArrivalTime:`/`Apparently-To:`/`X-Apparently-To:` は届いたメールに存在しないはずの残渣 — エクスポート品・手作り生成の兆候で、Apparently-To は Bcc 宛先の露出にもなる。
- **修正**: `has_draft_residue` — ヘッダ部で残渣欄を検出 → `Envelope.draft_residue` → render_risks 警告。
- **教訓**: 差出人の机の中にしまってあったはずの控えが届いた葉書。

### Security — D1381: SpamAssassin 判定欄 (X-Spam-Status 等) の自称が未検査

- **問題**: `X-Spam-Status:`/`X-Spam-Flag:`/`X-Spam-Level:`/`X-Spam-Bar:`/`X-Spam-Checker-Version:` 等の**判定結果**欄 — 「無害と判定済み」の体裁を送信側が書き込める。D363 は内訳欄のみ対象で判定欄そのものは未検査だった。
- **修正**: `has_spam_verdict_claim` — ヘッダ部で判定欄を検出 → `Envelope.spam_verdict_claim` → render_risks 警告。
- **教訓**: 「この書類は無害と判定済み」と内容側が印字する申請書。

### Security — D1382: 廃止済み整合性欄 (Content-MD5 等) の自称が未検査

- **問題**: `Content-MD5:` (RFC 1864・廃止)/`Content-Features:`/`Content-Alternative:`/`Content-Digest:` は「内容は照合済み・規格どおり」の体裁を送信側が書き込む欄 — 実際の検証なしに出せる自称印。
- **修正**: `has_integrity_claim` — ヘッダ部で該当欄を検出 → `Envelope.integrity_claim` → render_risks 警告。
- **教訓**: 検査済みの印を検査官ではなく出品側が捺す箱。

### Security — D1383: 記録抑制要求ヘッダ (X-No-Archive 等) が未検査

- **問題**: `X-No-Archive:`/`Restrict:`/`X-Ack:` 等は保存・記録を抑制する要求欄 — 「痕跡を残すな」の要求は証拠隠滅を図る送信側の兆候。
- **修正**: `has_suppression_claim` — ヘッダ部で該当欄を検出 → `Envelope.suppression_claim` → render_risks 警告。
- **教訓**: 「この手紙は読んだら捨てろ」と消印欄に書く葉書。

### Security — D1384: アドレス欄 addr-spec 位置の encoded-word が未検査

- **問題**: `From: =?utf-8?q?x?=@evil.example` や `From: <a=?utf-8?b?Yg==?=c@x>` — encoded-word がアドレス部分に混入すると、「復号してから addr-spec を読む実装」と「そのまま読む実装」で抽出アドレスがずれる (D1335 の構文版)。
- **修正**: `has_encoded_word_addr_spec` — From/Sender/Reply-To/To/Cc/Bcc/Resent-From の `<…>` 内部と `@` 直前に `=?…?=` を検出 → `Envelope.encoded_word_addr_spec` → render_risks 警告。
- **教訓**: 住所の途中に暗号が挟まれた宛名は、翻訳係ごとに別の家へ届ける。

### Security — D1377: message/* パートの base64/QP CTE が未検査

- **問題**: RFC 2046 §5.2.1 は `message/*` の CTE を 7bit/8bit/binary に限定 — base64 で .eml を包むと「パートをそのまま走査する」検査系は内側メッセージのヘッダを一切読めない。D1293 は `multipart/*` のみ対象だった。
- **修正**: `has_encoded_message_part` — `Content-Type: message/*` と base64/QP CTE が同一ヘッダ run に同居する形を検出 → `Envelope.encoded_message_part` → render_risks 警告。
- **教訓**: 書類束をさらに封筒に入れて密封する梱包は、中の宛名を書記に読ませない。

### Security — D1378: multipart/signed の署名パート欠落が未検査

- **問題**: `multipart/signed` は「本体 + 署名」の2パート構造 — 署名型パート (`application/pgp-signature`/`pkcs7-signature` 等) が無いまま signed を名乗ると「検証不能な署名付き体裁」になる。`protocol=` の言及だけでは署名は存在しない。
- **修正**: `has_unsigned_signed_container` — 外側が multipart/signed で、いずれかのパートの `Content-Type` が署名型でない構造を検出 → `Envelope.unsigned_signed_container` → render_risks 警告。
- **教訓**: 「封印済み」と書かれた箱に封印そのものが入っていない荷物。

### Security — D1379: In-Reply-To/References の自己参照が未検査

- **問題**: 返信系ヘッダが自分の `Message-ID` を参照するメッセージは「実在スレッドへの続き」を装う偽造形 — スレッドインデックスで自己ループや親子誤判定を誘発する。
- **修正**: `has_self_reply_ref` — Message-ID の `<…>` を抽出し、In-Reply-To/References の各 `<…>` と照合 → `Envelope.self_reply_ref` → render_risks 警告。
- **教訓**: 「この手紙はこの手紙への返信です」と名乗る葉書は、紐付け係を迷わせる。

### Security — D1380: 期限自称ヘッダ (Expires/Reply-By 等) が未検査

- **問題**: `Expires:`/`Reply-By:`/`Expiry-Date:` は送信側が「期限」を記す欄 — 日付で急かせる圧力表示 (D1340 `X-Priority` の期限版)。正規 MUA はほぼ生成しない。
- **修正**: `has_deadline_claim` — ヘッダ部でこれらの欄を検出 → `Envelope.deadline_claim` → render_risks 警告。
- **教訓**: 「今日中に返せ」と差出人が印字する葉書 — 催促の口上を封筒に書く手口。

### Security — D1375: カレンダー招待の非招待系 METHOD (CANCEL 等) が未検査

- **問題**: `METHOD:CANCEL` は UID 一致の既存イベントをカレンダーから**消す**指示、`REPLY`/`DECLINE`/`COUNTER` 系は出席応答の記録、`REFRESH`/`ADD` は照会・追記 — 送信側の自称だけで状態を書き換える。第三者が UID を盗んで偽 CANCEL を送れば実在の会議が消える (calendar spoofing)。`detect_auto_registration_abuse` は REQUEST/PUBLISH のみ対象だった。
- **修正**: `detect_method_spoof` + `CalendarRisk::MethodSpoof` — 非招待系 METHOD を検出し Caution 級で通知 (正当な取り消しも同形のため Danger にはしない)。
- **教訓**: 「その会合は無かったことにせよ」という口上は、誰が言ったかを見ない係に本物と同じ効き目を持つ。

### Security — D1376: text/enriched / text/richtext の廃止済み形式が未検査

- **問題**: `text/enriched` (RFC 1896) と `text/richtext` (RFC 1341) は廃止済みの簡易マークアップ — `<bold>` 等のタグを解釈する表示器と平文表示する表示器で本文の見え方がずれ、検査の目が平文として通す死角になる。
- **修正**: `has_enriched_text_type` — CT 宣言のメディア型が enriched/richtext を検出 → `Envelope.enriched_text_type` → render_risks 警告。
- **教訓**: もう誰も使わない書式の書類は、読み手ごとに別の文になる。

### Security — D1373: 異常に深い multipart 入れ子が未検査

- **問題**: 4 階層以上の multipart は正当用途がほぼ無く、再帰パーサへのリソース消費を狙った matryoshka 構造 — 各層で全文を再走査する実装は CPU/メモリを消費される。
- **修正**: `has_deep_multipart_nesting` — 宣言 boundary スタックで実効深さを計測、4 以上で検出 → `Envelope.deep_multipart_nesting` → render_risks 警告。
- **教訓**: 箱を開けるたび箱が出る梱包は、開ける係を疲弊させる荷物。

### Security — D1374: パートヘッダ内の MIME-Version が未検査

- **問題**: `MIME-Version:` はメッセージ外側専用の欄 — パート側に混入すると「MIME ではない」と解釈する実装と無視する実装で以降の構造解釈がずれる。
- **修正**: `has_part_mime_version` — 宣言 boundary で区切られたパートのヘッダ run に `mime-version:` を検出 → `Envelope.part_mime_version` → render_risks 警告。
- **教訓**: 荷物一つひとつの札に便の規格番号が書いてある梱包は、仕分け係を迷わせる。

### Security — D1371: 宣言 base64 パートの規格超過行が未検査

- **問題**: RFC 2045 は base64 行を 76 字に制限 — 超過行は折り返す/切る/そのまま読むで復号バイトがずれ、添付内容が受取側で別物になる。D1316 は文字種の異常、D1362 は未宣言 — 行長は未検査だった。
- **修正**: `has_overlong_base64_line` — 宣言 base64 パート本文の 76 字超行を検出 → `Envelope.overlong_base64_line` → render_risks 警告。
- **教訓**: 規格より長い帯で巻かれた荷物は、係ごとに違う所で帯を切る。

### Security — D1372: 同一ヘッダ欄の encoded-word charset 混在が未検査

- **問題**: `=?UTF-8?…?= =?ISO-2022-JP?…?=` のように一欄で文字コードが混ざると、部分ごとに復号して繋ぐ実装と一括解釈する実装で表示名・件名がずれる。正規 MUA は一欄一 charset。
- **修正**: `has_mixed_encoded_charset` — 論理行内の encoded-word charset を集め、2 種以上なら検出 → `Envelope.mixed_encoded_charset` → render_risks 警告。
- **教訓**: 一枚の名札に二種類の文字体系が混ざる名は、翻訳係ごとに別の名前になる。

### Security — D1369: 複数パートの Content-ID/Content-Location 重複が未検査

- **問題**: multipart/related で同じ `cid:`/`Content-Location:` を名乗る二つのパートは、参照解決が「先に来る実装/後に来る実装」でずれる — HTML 本文が参照する画像を別内容に差し込める (cid 衝突)。
- **修正**: `has_duplicate_content_id` — Content-ID/Content-Location の値を収集し重複を検出 → `Envelope.duplicate_content_id` → render_risks 警告。
- **教訓**: 同じ札番号を名乗る二つの荷物 — 棚から取る係によって別物が届く。

### Security — D1370: 差出人欄のドメインリテラルが未検査

- **問題**: `From: admin@[192.168.0.1]`/`root@[IPv6:...]` はドメイン名を持たない自称 — ドメイン評判・SPF/DMARC の対象外で、内部宛・システム通知を装う手作り生成品の兆候。
- **修正**: `has_literal_domain_sender` — From/Sender/Reply-To の `@` 後が `[` で始まる形を検出 → `Envelope.literal_domain_sender` → render_risks 警告。
- **教訓**: 町名でなく座標で住処を名乗る差出人。

### Fixed — Devin Review 指摘 (ラウンド55 追録)

- **修正**: Devin Review の指摘8件を精査し実バグ5件を修正:
  - `has_missing_part_content_type` — 本文中の `-- ` 署名区切りが宣言 boundary と見なされ偽パート run を開始していた問題を、宣言 boundary 一覧 (`declared_boundaries`) で厳密判定するよう修正 (BUG_0002)。
  - `has_odd_mime_version` — `MIME-Version:` 値が FWS 折りたたみで次行に分かれると値比較が失敗していた問題を、論理行化してから比較するよう修正 (BUG_0003)。
  - `has_empty_group_syntax` — `user@[IPv6:2001:db8::1]` のドメインリテラル内 `:` をグループ区切りと誤認していた問題を、`in_lit` フラグで `[...]` 区間を除外するよう修正 (BUG_0004)。
  - `has_ansi_escape_body`/`has_bidi_override_body` — base64/QP 符号化パートの本文を復号せず生テキストで走査していたため、符号化で制御列を隠す回避が可能だった問題を、`decode_transfer_body`/`decode_qp_body` で復号後に検査するよう修正 (SEC_0002)。
  - `has_undeclared_base64_block` — 単パートのみ走査で multipart 内の非宣言 b64 本文を見逃していた問題を、パート単位の CTE 状態機械に書き換え (SEC_0003)。
- **回答のみ**: 残り指摘は (a) 全走査が線形・単一パスで指数爆発なし (リソース枯渇指摘は設計上成立せず)、(b) 生 UTF-8 ヘッダは RFC 6532 SMTPUTF8 で合法 (D1304 が別途非 UTF-8 を検出済み) — として PR 上で理由を記載。

### Security — D1367: 本文の ANSI/ターミナル制御列が未検査

- **問題**: 本文の ESC `[`/`]`/`P`/`X`/`^`/`_` 制御列は、ターミナル系表示器やログビューアで開いた際に表示内容を改竄する (OSC 8 偽リンク・OSC 52 クリップボード書き換え・消去)。メール本文で正当な用途は無い。
- **修正**: `has_ansi_escape_body` — 非符号化パートの本文領域で ESC+制御列を検出 → `Envelope.ansi_escape_body` → render_risks 警告。
- **教訓**: 見せられた文字が消える手紙は、書かれた内容を疑う。

### Security — D1368: 本文の bidi 上書き制御文字が未検査

- **問題**: 本文中の U+202A–U+202E (override) は表示順を反転させる trojan-source 型偽装 — 件名側は D1302 で済みだが本文側は未検査だった。
- **修正**: `has_bidi_override_body` — 非符号化パートの本文領域で override 系を検出 → `Envelope.bidi_override_body` → render_risks 警告。isolate 系 (U+2066–9) は RTL 言語の正当利用があるため対象外。
- **教訓**: 文字の順番を裏返す墨が混じった手紙。

### Security — D1365: 添付名のコロン (Windows ADS) が未検査

- **問題**: `filename="invoice.pdf:hidden.exe"` の `名:型` は Windows で Alternate Data Stream として別名に書き込まれる — 表示名と実際の格納先がずれ、拡張子検査を素通りする格納先偽装。
- **修正**: `filename_anomalies` に `ads_stream` 兆候を追加 — `:` 含有名でリスク警告 (既存の添付走査経路に合流)。
- **教訓**: 名札に二つの名前を重ね書きした荷物は、棚ごとに別の棚へ置かれる。

### Security — D1366: 非クオート boundary 値内の `;` 混入が未検査

- **問題**: `boundary=a;b` はトークンで切る実装が `a`、行末まで読む実装が `a;b` を区切りとし、パート構造が完全にずれる (D1281/D1294/D1311 boundary 系の姉妹)。
- **修正**: `has_boundary_semicolon` — CT ヘッダの非クオート `boundary=` 値が `;` で切れた後に `key=value` でない断片が続く形を検出 → `Envelope.boundary_semicolon` → render_risks 警告。
- **教訓**: 区切り札の途中に切れ目があると、荷物係ごとに違う札を見る。

### Security — D1363: 空・未終端グループ構文が未検査

- **問題**: `To: undisclosed-recipients:;` は宛先欄を満たしながら宛先を一切見せない一斉送信の書式 — D1339 (宛先全欠落) の回避経路。`:` 後に `;` が無い未終端グループも実装間で解釈がずれる。
- **修正**: `has_empty_group_syntax` — アドレス欄のクオート・コメント外の `:` を検査、空または未終端なら検出 → `Envelope.empty_group_syntax` → render_risks 警告。
- **教訓**: 宛先欄の名札が空なら、誰にも読めない宛先。

### Security — D1364: Usenet 制御ヘッダ混入が未検査

- **問題**: `Control:`/`Supersedes:`/`Cancel-Lock:`/`Cancel-Key:`/`Approved:` 等はメールでは意味を持たない — 存在自体が制度混在・手作り生成の兆候 (news 制御メッセージの流用)。
- **修正**: `has_usenet_control_header` — 外側ヘッダに制御系ヘッダを検出 → `Envelope.usenet_control_header` → render_risks 警告。`Approved:` はメールでも用いられるため `@` 必須。
- **教訓**: 別の郵便制度の消印が貼られた封筒。

### Security — D1361: 偽返信 (Re:/Fwd: だが threading 参照無し) が未検査

- **問題**: `Subject: Re: …` を名乗りながら `In-Reply-To:`/`References:` が無いメッセージは、実 MUA では作れない「続きの体裁」の偽装 (BEC の既存スレッド演出)。
- **修正**: `has_fake_reply_claim` — 件名が `re:`/`fwd:`/`fw:` で始まり threading ヘッダが無いと検出 → `Envelope.fake_reply_claim` → render_risks 警告。
- **教訓**: 「続き」と名乗る封筒に綴じ紐が無ければ別物。

### Security — D1362: 宣言されていない base64 本文ブロックが未検査

- **問題**: 単パートで `Content-Transfer-Encoding` が base64 でないのに本文が base64 形の行で埋まると、宣言だけを復号する検査にペイロードが見えない (D1316 は宣言済みの破損のみ)。
- **修正**: `has_undeclared_base64_block` — 本文の b64 形連続行 (≥2 行または 48 字超の単行) を検出 → `Envelope.undeclared_base64_block` → render_risks 警告。multipart・宣言済み base64 は対象外。
- **教訓**: 「平文です」と書かれた箱の中に暗号の束。

### Security — D1358: 無名 attachment パートが未検査

- **問題**: `Content-Disposition: attachment` 宣言で filename/name が一切無いパートは、自動命名する実装 (attachment.bin・part2.exe) と空欄表示する実装で見える添付名がずれる。
- **修正**: `has_unnamed_attachment` — パートのヘッダ run 単位で CD=attachment かつ filename/name 無しを検出 → `Envelope.unnamed_attachment` → render_risks 警告。
- **教訓**: 名無しの荷物は開ける係ごとに別の札が付く。

### Security — D1359: アドレスドメインの非 ASCII が未検査

- **問題**: `u@例え.jp` のような Unicode ドメインは、そのまま表示する実装と punycode/拒否する実装で差出人ドメインが違う顔になる (IDN ホモグラフの宛名版)。
- **修正**: `has_non_ascii_addr_domain` — アドレス欄のコメント・クオートを除いたトークンの `@` 以降に高位バイトを検出 → `Envelope.non_ascii_addr_domain` → render_risks 警告。
- **教訓**: 異字の町名は読み手によって別の町に見える。

### Security — D1360: filename / filename* の両記法不一致が未検査

- **問題**: 同一パートの `filename=` と `filename*=` (RFC 2231) が別の値を名乗ると、`*` を優先する実装と無視する実装で添付名がずれる。
- **修正**: `has_conflicting_filename` — 両キーの値を %復号して比較、不一致なら検出 → `Envelope.conflicting_filename` → render_risks 警告。一致する併記 (正規) は不発火。
- **教訓**: 同じ荷物に二枚の名札 — 読む係で別の名になる。

### Security — D1355: 稀な multipart サブタイプが未検査

- **問題**: `multipart/parallel`/`byteranges`/`appledouble` 等はメールでの正当用途が無く、各パートの扱い (並列表示・範囲結合) が実装間でずれる死角。
- **修正**: `has_exotic_multipart_subtype` — 既知正規形 (mixed/alternative/related/signed/encrypted/digest/report/form-data) 以外を検出 → `Envelope.exotic_multipart_subtype` → render_risks 警告。`x-mixed-replace` は D1348 の専用警告に委譲。
- **教訓**: 珍しい器は「どう開けるか」が係ごとに違う。

### Security — D1356: メディア型トークンの形の崩れが未検査

- **問題**: `Content-Type: text/a/b`・`text/`・`/plain`・空白混入は型解釈が実装間でずれる (subtype 欠落は D1320)。
- **修正**: `has_malformed_media_type` — CT 値のメディア型トークンを `type/subtype` の形で検査 → `Envelope.malformed_media_type` → render_risks 警告。
- **教訓**: 型名の形が崩れれば「何と書かれたか」は読み手次第。

### Security — D1357: 添付名の %XX エスケープ断片が未検査

- **問題**: 素の `filename=`/`name=` 内の `%20` 等は、パーセント復号する実装としない実装で添付名がずれる (RFC 2231 `filename*=` は正規符号化で対象外)。
- **修正**: `has_percent_encoded_filename` — CT/CD の正規キー値内の `%`+hex2桁を検出 → `Envelope.percent_encoded_filename` → render_risks 警告。
- **教訓**: 同じ書類が「復号する係」と「しない係」で別名になる。

### Security — D1353: アドレスの dot-atom 違反が未検査

- **問題**: `a..b@x`・`.a@x`・`user@internal` 等の addr-spec 違反は、厳格実装が拒否し寛容実装が受理・正規化する — 照合・表示が読み手でずれる。
- **修正**: `has_malformed_addr_spec` — アドレス欄の各 `local@domain` を dot-atom で検査 → `Envelope.malformed_addr_spec` → render_risks 警告。domain literal・FQDN 末尾ドット (D1299) は対象外。
- **教訓**: 形の崩れた宛名は「誰が読むか」で受取人が変わる。

### Security — D1354: アドレス欄の `<` `>` 不対応が未検査

- **問題**: `From: CEO <ceo@x` のように route-addr の開閉がずれると、アドレス抽出が実装間で分かれて差出人欄が違う顔になる。
- **修正**: `has_unbalanced_route` — アドレス欄のクオート・コメント外 `<` `>` を計数、不一致なら検出 → `Envelope.unbalanced_route` → render_risks 警告。
- **教訓**: 括弧の対応は構造の約束 — 崩れれば囲まれたものが読み手で変わる。

### Security — D1350: Content-Type 無宣言パートが未検査

- **問題**: boundary 行で始まるが `Content-Type:` を持たないパートは、RFC 2046 の既定 `text/plain` を適用する実装とスニッフィングに頼る実装で読み手がずれる。
- **修正**: `has_missing_part_content_type` — `--` run が CT 無しで終われば検出 → `Envelope.missing_part_content_type` → render_risks 警告。
- **教訓**: 「書かれていない型」は書かれた型より解釈が割れる。

### Security — D1351: CT/CD パラメータ値内の encoded-word が未検査

- **問題**: `filename="=?UTF-8?B?…?="` — RFC 2047 はパラメータ値内の encoded-word を認めない (RFC 2231 が正規) が、復号する表示側としない側で添付名がずれる。
- **修正**: `has_param_encoded_word` — CT/CD 行の `;` 以降に `=?` があれば検出 → `Envelope.param_encoded_word` → render_risks 警告。
- **教訓**: 正規の符号化方式が別にある場所に別方式を混ぜれば読み手が割れる。

### Security — D1352: `multipart/digest` コンテナが未検査

- **問題**: digest のメンバーは既定 `message/rfc822` (RFC 2046 §5.1.5)。既定値を知らない検査は宣言無しの入れ子メールを見逃す。
- **修正**: `has_digest_container` — CT が `multipart/digest` なら検出 → `Envelope.digest_container` → render_risks 警告。
- **教訓**: 既定値の中身は宣言されずに届く — 既定を知らない検査は見えない。

### Security — D1347: パート宣言の message/* サブタイプが未検査

- **問題**: `message/delivery-status`・`message/partial`・`message/external-body` 等は添付側で D1266 が検査するが、パート宣言位置では未検査。「メッセージ型」を名乗るだけで内容走査を避ける死角。
- **修正**: `has_message_subtype_part` — 外側・パート run の CT が `message/rfc822` 以外の `message/*` なら検出 → `Envelope.message_subtype_part` → render_risks 警告。
- **教訓**: 「添付」と「パート宣言」は別の入口 — 同じ型でも通る場所が違う。

### Security — D1348: `multipart/x-mixed-replace` が未検査

- **問題**: push 型 — 後続パートが先の内容を逐次置き換える。描画実装では表示内容が受信後に動的にすり替わり、静止検査と実表示がずれる。メールでの正当な用途は無い。
- **修正**: `has_mixed_replace` — CT が `multipart/x-mixed-replace` なら検出 → `Envelope.mixed_replace` → render_risks 警告。
- **教訓**: 「時間と共に変わる文書」は静止検査では見えない。

### Security — D1349: 暗号化内容の検査不能が未通知

- **問題**: `multipart/encrypted`・`application/pkcs7-mime`・本文の `-----BEGIN PGP MESSAGE-----` 等は内容が一切の走査を素通りする。正当利用でも「検査不能」は通知すべき情報。
- **修正**: `has_opaque_encrypted_content` — CT が暗号化系または本文に BEGIN PGP/PKCS7/CMS ブロックがあれば検出 → `Envelope.opaque_encrypted` → render_risks 注意喚起。
- **教訓**: 検査できないという事実自体が検査結果。

### Security — D1344: HTTP フレーミングヘッダが未検査

- **問題**: `Content-Length:`/`Transfer-Encoding:`/`Host:`/`Connection:` は HTTP の転送制御ヘッダで RFC 5322 メールには意味を持たない。存在自体が手作り生成・プロキシ連結ミス・別プロトコルペイロード混入の兆候。
- **修正**: `has_http_framing_headers` — 外側ヘッダに該当欄があれば検出 → `Envelope.http_framing_headers` → render_risks 警告。`Content-Transfer-Encoding:` は別名で対象外。
- **教訓**: プロトコル違いの欄は届け方そのものが偽物である印。

### Security — D1345: `text/rfc822-headers` パートが未検査

- **問題**: RFC 1892 のヘッダのみ内容型。中身は「ヘッダの形をした本文」でヘッダ走査が届かず、偽造 Received/From を潜ませる死角。
- **修正**: `has_rfc822_headers_part` — 外側・パート run の CT が `text/rfc822-headers` なら検出 → `Envelope.rfc822_headers_part` → render_risks 警告。
- **教訓**: 「ヘッダの形をした内容」は走査の抜け道 — 内容としてのヘッダと構造としてのヘッダは別物。

### Security — D1346: CT/CD パラメータ値内のコメントが未検査

- **問題**: `boundary=ab(junk)cd` のようなクオート外コメントは、剥がす実装と値の一部と見る実装で boundary/filename 等の値がずれる (D1281/D1296 同族)。
- **修正**: `has_param_value_comment` — CT/CD 行でクオート外の `(`/`)` を検出 → `Envelope.param_value_comment` → render_risks 警告。クオート内の括弧は正規ファイル名として対象外。
- **教訓**: 値の中の注釈は値の解釈を割く — コメントを認める実装差異は差異の材料。

### Security — D1342: メッセージ先頭の BOM が未検査

- **問題**: RFC 5322 メッセージに BOM は存在しない。`EF BB BF` (UTF-8)・`FF FE`/`FE FF` (UTF-16) で始まるメッセージは、BOM を剥がす実装とそのまま第1ヘッダ行に載せる実装で以降の全ヘッダ解釈がずれる。UTF-16 のメッセージは ASCII 系パーサで全体が死角になる。
- **修正**: `has_leading_bom` — 先頭バイトが BOM なら検出 → `Envelope.leading_bom` → render_risks 警告。
- **教訓**: ストリームの先頭1バイト目は全ヘッダの原点 — 原点がずれれば全てがずれる。

### Security — D1343: multipart/alternative 内の添付メンバーが未検査

- **問題**: `multipart/alternative` は同一本文の代替表現の場。attachment 形 (CD attachment・filename=・CT name=) のメンバーは構造の誤用で、メンバー扱いが実装間でずれる — 「代替の一つとして隠す」検査系から添付が見えない。
- **修正**: `has_alternative_attachment` — 外側 CT が alternative で、メンバー run に attachment/filename=/name= があれば検出 → `Envelope.alternative_attachment` → render_risks 警告。
- **教訓**: 「代替表現の場」はパート種別を限定する — 場違いのパートは構造の誤用。

### Security — D1340: 緊急性の自称ヘッダが未検査

- **問題**: `X-Priority: 1`/`2`・`Importance: high`/`urgent`・`Priority: urgent`・`X-MSMail-Priority: high` は送信側が書き込む「急げ」の体裁 — BEC で判断を急かせる定番の社会的圧力だが未検査だった。
- **修正**: `has_urgency_claim` — 外側ヘッダで当該値が高優先度なら検出 → `Envelope.urgency_claim` → render_risks 警告 (「を送信側が書く兆候です」サフィックスで DMARC pass 時に沈静化する自称系)。
- **教訓**: 心理的圧力もヘッダで自称される — 体裁の自称は内容の異常と同じく兆候。

### Security — D1341: encoded-word 復号後の構文文字が未検査

- **問題**: D1324 は復号後の制御文字のみ見るが、`<`/`>`/`"`/`(`/`)`/`\` を含む復号結果を持つ encoded-word は、復号後にヘッダ値を再解釈する実装で引用・コメント・アドレス構造を書き換える — 転送形と復号形で差出人がずれる。アドレス欄では復号結果の `@` も構造を変える。
- **修正**: `has_structural_encoded_word` — ヘッダ run 内の encoded-word を全 `?=` 終端候補で復号し、構文文字を検出。アドレス欄では `@` も対象 → `Envelope.structural_encoded_word` → render_risks 警告。
- **教訓**: 復号は防御の終点ではなく再解釈の起点 — 構文を再び書き込める復号物は制御文字と同じ危険。

### Security — D1338: In-Reply-To/References の非 msgid 値が未検査

- **問題**: `In-Reply-To:`/`References:` が `<id@…>` の形を持たない値 (空値・裸文字列・`@` 無しトークン・夾雑テキスト) は、参照できない偽のスレッド文脈 — 「既存スレッドの続き」の体裁を作る工作 (D1336 の姉妹)。
- **修正**: `has_malformed_thread_refs` — 外側ヘッダで当該欄の値が空・`<…@…>` トークンを欠く・トークン外に非空白文字を持つ場合に検出 → `Envelope.malformed_thread_refs` → render_risks 警告。
- **教訓**: 「続きの体裁」は Subject の Re: だけでなく参照欄の値でも偽装される。

### Security — D1339: 宛先欄の全欠落が未検査

- **問題**: 外側ヘッダに To/Cc/Resent-To/Resent-Cc が一切無い (または値が全て空) メッセージは、宛先を見せない BCC 一斉送信の配送形状 — 受取人を名指ししない大量送信の形。Bcc 欄は配送時除去されるため、届いた側で宛先が見えないこと自体が形の異常。
- **修正**: `has_no_recipient_headers` — 宛先欄が無い・値が空なら検出 → `Envelope.no_recipient_headers` → render_risks 警告。
- **教訓**: 「欄の値の異常」だけでなく「欄そのものが無い配送形状」も兆候として扱う。

### Security — D1335: 表示名がメールアドレス形で実アドレスと不一致でも未検査

- **問題**: `From: "security@apple.com" <attacker@evil.example>` — 表示名だけを出す実装は表示名中のアドレスを差出人と誤認する。差出人欄偽装の定番形で未検査だった。
- **修正**: `has_address_display_name` — From の `<…>` ルートアドレスと、引用・コメントを剥がした表示名を比較。表示名が `@` を持ちルートアドレスと一致しなければ検出 → `Envelope.addr_in_display_name` → render_risks 警告。自己言及 (`"me@x" <me@x>`) は不発火。
- **教訓**: 表示名と実値の不一致は文字種 (D1275) だけでなく「表示名自体がアドレスに見える」形でも起きる。

### Security — D1336: Message-ID 欠落・形の崩れが未検査

- **問題**: RFC 5322 は Message-ID を SHOULD とし通常の送信経路は必ず付与するが、欠落や `<id@domain>` の形を持たない値は手作り生成品の兆候で、スレッド参照検査の材料も失わせる (D1278 Date 欠落の姉妹)。
- **修正**: `has_odd_message_id` — 外側ヘッダで `Message-ID:` が無い、または `<…@…>` の形にならない値を検出 → `Envelope.odd_message_id` → render_risks 警告。折り畳み継続行は FWS 展開後に評価。
- **教訓**: 必須級欄の「無い」だけでなく SHOULD 級欄の欠落も兆候として扱う。

### Security — D1337: Content-Disposition の非標準型が未検査

- **問題**: `Content-Disposition:` の型は RFC 2183/6266 で inline|attachment のみ標準。`form-data` 等の拡張トークン・空値は「添付扱いする実装」と「ヘッダを無視する実装」で解釈がずれ、添付一覧に現れない死角になる。
- **修正**: `has_odd_disposition_type` — 外側 + 各パートのヘッダ run を走査し、CD 値の第一トークンが inline/attachment 以外 (空値含む) なら検出 → `Envelope.odd_disposition_type` → render_risks 警告。
- **教訓**: 「この値をどう解釈するかが実装依存」の指定は、標準外の値そのものが兆候。

### Security — D1333: 読了通知請求ヘッダが未検査

- **問題**: `Disposition-Notification-To:` (RFC 8098 MDN)・`Return-Receipt-To:`・`X-Confirm-Reading-To:`・`Return-Receipt-Requested:` は開封を送信側に通知する仕掛け — メールトラッカーと同型の生存確認・開封時刻偵察経路だが未検査だった。
- **修正**: `has_receipt_request` — 外側ヘッダに該当ヘッダがあれば検出 → `Envelope.receipt_request` → render_risks 警告。
- **教訓**: 「見たことを送信側が知る」経路はリモート画像と同型 — ヘッダ形態のものも兆候として扱う。

### Security — D1334: addr-spec を持たない From が未検査

- **問題**: `From: "CEO"` (表示名のみ) や `From:` (空値) にはルーティング可能な差出人アドレスが無い — 名前だけを表示する実装と「不明」を出す実装でずれ、表示名だけの偽装材料になる (D1325 は「多すぎる From」、こちらは「アドレスの無い From」)。
- **修正**: `has_degenerate_from_addr` — 引用・コメントを剥がした From 値に `@` が無ければ検出 → `Envelope.degenerate_from` → render_risks 警告。引用・コメント内の `@` はアドレスと見なさない。
- **教訓**: 一意欄の欠落形には「多い」だけでなく「無い」もある。

### Security — D1331: 受信メッセージの Bcc 残存が未検査

- **問題**: `Bcc:` は宛先に見せない欄で配送時に除去されるのが一般 — 受信メッセージへの残存は手作り生成か経路異常の兆候であり、Bcc 宛先が受信者に露出する情報流出でもある。
- **修正**: `has_bcc_header` — FWS 展開後の外側ヘッダに `bcc:` があれば検出 → `Envelope.bcc_header` → render_risks 警告。入れ子 .eml 内部の Bcc はそのメッセージ自身の属性のため対象外。
- **教訓**: 「届くはずのない欄」が届いていること自体が兆候。

### Security — D1332: `Content-Base:` のリモート URL が未検査

- **問題**: RFC 2557 (MHTML) の `Content-Base:` は相対参照の解決先を外部に向ける — 本体は空・無害のまま表示時リモートフェッチを成立させる。D1284 は `Content-Location:` のみ検査で姉妹ヘッダが残っていた。
- **修正**: `has_remote_content_base` — `content-base:` 値が http/https/ftp なら検出 → `Envelope.remote_content_base` → render_risks 警告。cid: 等ローカル参照は対象外。
- **教訓**: 同型ヘッダは対で見る — 片方だけ塞ぐと経路は残る。

### Security — D1329: charset 宣言と本文実バイトの矛盾が未検査

- **問題**: `charset=us-ascii` を名乗る本文に高位バイト、`charset=utf-8` を名乗る本文に不正 UTF-8 列があると、置換文字にする実装と生バイトを保持する実装で本文がずれる — 表示側でのみ攻撃文字列になる差異。
- **修正**: `has_charset_body_mismatch` — ヘッダ run ごとに charset/CTE/multipart を評価し、非符号化本文のバイト列を charset に照合 → `Envelope.charset_body_mismatch` → render_risks 警告。base64/QP は生行が判定材料でないため対象外。
- **教訓**: 宣言は契約 — charset は「本文バイト列の読み方」の宣言であり、実バイトとの不一致は読み手ごとの解釈差分。

### Security — D1330: `Name:` の形を持たないヘッダ行が未検査

- **問題**: ヘッダ run 中にコロンを欠く行・空名・名前中に非許可文字を含む行があると、そこでヘッダ終端と見る実装・行を捨てる実装・結合する実装で以降の解釈がずれる (D1305 の空白前置名はこの一般形の一部)。
- **修正**: `has_malformed_header_line` — ヘッダ run の非継続行が `表示可能 ASCII 名 + :` の形を持つか検査 → `Envelope.malformed_header_line` → render_risks 警告。
- **教訓**: 欄の形そのものが崩れている行は、どこまでが欄かの読み手間差分。

### Security — D1327: ヘッダ内の非許可制御バイトが未検査

- **問題**: ヘッダ値に許される制御文字は HTAB のみだが、FF/VT/DEL 等の混入は未検査だった — FF/VT は改頁・改行として描画される実装があり件名・差出人欄の見え方を偽装する。
- **修正**: `has_ctl_bytes_in_headers` — 外側+パートヘッダ run の行を走査し `\t`/`\r`/NUL 以外の <0x20 と DEL を検出 → `Envelope.ctl_bytes_in_headers` → render_risks 警告 (NUL は D1303、裸 CR は D1307 が担当)。
- **教訓**: 制御文字は「見えない改行」— 欄の表示形そのものを偽装する材料。

### Security — D1328: 7bit 宣言と矛盾する高位バイト本文が未検査

- **問題**: `Content-Transfer-Encoding: 7bit` を明示したパートの本文に 0x80 以上のバイトは、高位ビットを落とす実装と保持する実装で本文がずれる。既定 7bit (CTE 無し) の高位バイトは実害として広く見られるため対象外にし、明示宣言との矛盾のみを捉える。
- **修正**: `has_8bit_body_with_7bit_cte` — ヘッダ run ごとに CTE==7bit かつ非 multipart を判定し、その本文に ≥0x80 バイトがあれば検出 → `Envelope.eightbit_body_7bit` → render_risks 警告。
- **教訓**: 宣言は契約 — 宣言値と実バイトの不一致は読み手ごとの解釈差分。

### Security — D1325: From の複数アドレス/経路指定形が未検査

- **問題**: `From: a@x, b@y` の複数 mailbox (RFC 5322 は Sender: を必須とする特殊形) や `<@relay:user@host>` の obs-route-addr は、単一差出人と見る実装と先頭/末尾を採用する実装で差出人欄がずれる (複数 From のパーサ差異は mutt/Thunderbird 系 CVE の実績形)。
- **修正**: `has_multi_addr_from` — 引用・コメントを剥がした From 値に `,` または `<@` があれば検出 → `Envelope.multi_addr_from` → render_risks 警告。`"Tanaka, Taro"` の氏名カンマは不発火。
- **教訓**: 一意であるべき欄が「並び」の形をとること自体が兆候 — 採用する1件が実装で分かれる。

### Security — D1326: 実行形式メディア型の添付宣言が未検査

- **問題**: `application/x-msdownload`/`x-dosexec`/`hta`/`java-archive` 等の CT 値は、ファイル名とは独立に「実行物」を宣言する — 拡張子を見る検査は `readme.dat` 偽装をすり抜けるが、宣言側を見る検査が無かった。
- **修正**: `has_executable_content_type` — ヘッダ run の CT メディア型が実行形式型なら検出 → `Envelope.executable_content_type` → render_risks 警告。
- **教訓**: 「何が入っているか」の宣言は拡張子と別の経路 — 型が名乗る危険度を直接見る。

### Security — D1323: 非正規形 IP リテラルホスト URL が未検査

- **問題**: `http://2130706433/` (DWORD)・`http://0x7f000001/` (hex)・`http://0177.0.0.1/` (octal)・`http://127.1/` (短縮)・裸 IPv4 はブラウザ/inet_aton が IP に解釈するがドメイン評判リストの対象外 — 宛先が「ドメイン名の形」をしていないため評価系の盲点になる (SSRF 回避手法のメールリンク転用)。
- **修正**: `is_numeric_ip_host` — 全ラベルが数字のみ/``0x``hex のホストを Suspicious として評価 (quishing::evaluate_url で QR・本文リンク両方に効く)。
- **教訓**: 「ドメインかどうか」自体を疑う — 名の形をしていない宛先は評判照合が効かない。

### Security — D1324: encoded-word 復号後の制御文字が未検査

- **問題**: `=?UTF-8?B?DQo=?=` (CRLF) 等、encoded-word 自体は印字可能文字のみで合法だが、復号結果に制御文字が出るとヘッダ文字列への展開時に改行・終端が注入される (ヘッダ注入・表示偽装)。lenient 実装が text 内 `?` を許す形 (`=?x?Q?=09?=`) も復号器で読み方がずれる。
- **修正**: `has_control_encoded_word` — ヘッダ run の `=?charset?{B,Q}?text?=` をすべての `?=` 終端候補で評価・復号し、制御文字 (0x20 未満/0x7F) を検出 → `Envelope.control_encoded_word` → render_risks 警告。
- **教訓**: 符号化された欄は「復号した後の値」まで検査しないと、復号だけが見える文字が残る。

### Security — D1321: boundary 区切りの前方一致曖昧行が未検査

- **問題**: `--b` の直後に空白でも `--`+空白でもない内容が続く行 (`--bJUNK`/`--b--x`) は、厳密一致の実装では区切りでないが prefix 一致で区切る実装ではそこで分割される — mailsplit 系のパーサ差異。入れ子 boundary が外側の延長文字列のとき自然に発生する形でもある。
- **修正**: `has_ambiguous_boundary_line` — 宣言 boundary 値を収集し、全物理行で `--{b}` 直後の残部が空白のみ/`--`+空白のみ以外の行を検出 → `Envelope.ambiguous_boundary_line` → render_risks 警告。
- **教訓**: 区切りの一致は「行全体が合うか」が契約 — 前方一致だけで区切る実装とずれる。

### Security — D1322: TNEF (winmail.dat) 添付の検査死角が未検査

- **問題**: `application/ms-tnef`/`application/vnd.ms-tnef` (`winmail.dat`) は本文・添付を独自バイナリ内に内包し、TNEF を展開しない MIME 検査には内容が一切見えない — message/partial・未終了 multipart と同族のカプセル化死角。
- **修正**: `has_tnef_attachment` — CT メディア型または filename/name が `winmail.dat` のパートを検出 → `Envelope.tnef_attachment` → render_risks 警告。
- **教訓**: 独自カプセル化形式は「中身を見る器」を持たない検査に対し構造的な盲点を作る。

### Security — D1319: 退化添付名が未検査

- **問題**: `filename=""`・`filename="   "`・`filename=".."` 等の実質無名添付は、自動命名するメーラーと空欄のまま表示するメーラーで見え方がずれる (D1311 空 boundary・D1313 パス成分と同族の退化形)。
- **修正**: `has_degenerate_filename` — `filename=`/`name=` 値が空または空白/ドットのみなら検出 → `Envelope.degenerate_filename` → render_risks 警告。
- **教訓**: 名前欄の検査は「空・意味を成さない形」も含む — 実質無名は採番・表示・保存のどこでもずれを生む。

### Security — D1320: Content-Type の subtype 欠落が未検査

- **問題**: `Content-Type: text` 等の `/` を欠く値は、`text/plain` を既定値とする実装と受理しない実装で解釈がずれる (D1312 宣言値差異と同型)。メディア型の grammar 自体の違反。
- **修正**: `has_typeless_content_type` — 外側 + パートヘッダ run で `content-type:` のメディア型本体に `/` が無ければ検出 → `Envelope.typeless_content_type` → render_risks 警告。
- **教訓**: 「型/種別」の書式は両方の部分が必須 — 主値だけの欄は既定値の読み方が実装で分かれる。

### Security — D1317: boundary の bchars 外文字が未検査

- **問題**: boundary の字句は bchars (`ALPHA`/`DIGIT`/`'()+_,-./:=?`/space) に限定される (RFC 2046 §5.1.1)。`<`・`"`・`#` 等を含む値は受理してそのまま区切りに使う実装と拒否/切り詰める実装でパート構造がずれる (D1281/D1294/D1311 の字句側)。
- **修正**: `has_invalid_boundary_chars` — boundary= 値に bchars 外の文字があれば検出 → `Envelope.invalid_boundary_chars` → render_risks 警告。`_` は `----_=_NextPart` 型を生成する実装が広くあるため許容。
- **教訓**: 字句集合の検査も「実運用で一般的な逸脱」は許容する — 規格と実態の差を両方知る必要がある。

### Security — D1318: Windows 予約デバイス名の添付名が未検査

- **問題**: `NUL.exe`・`CON.pdf`・`COM1.scr` 等は Windows ではデバイスを指し通常ファイルとして保存できない — 拒否する環境と別名保存する環境で挙動がずれるほか意図的な工作の兆候。D1265/D1313 は形とパス成分のみ対象。
- **修正**: `has_device_filename` — `filename=`/`name=` の語幹 (最初の `.` まで) が CON/PRN/AUX/NUL/COM1-9/LPT1-9 と一致すれば検出 → `Envelope.device_filename` → render_risks 警告。
- **教訓**: 保存先 OS の予約語は跨環境の差異点 — 名が何を指すかは OS 依存。

### Security — D1315: QP 本文の不正エスケープが未検査

- **問題**: quoted-printable 本文で `=` は行末ソフトブレークか `=XX` のみ合法 (RFC 2045 §6.7)。`=xy` 等の不正エスケープは「残す」デコーダと「除去する」デコーダで本文がずれ、検査器と表示側で別の内容になる。
- **修正**: `has_invalid_qp_escapes` — `content-transfer-encoding: quoted-printable` のパート本文のみを対象に `=` 直後が 2 桁 hex でも行末でもない箇所を検出 → `Envelope.invalid_qp_escapes` → render_risks 警告。
- **教訓**: 転送符号の字句違反は復号差異の直撃点 — 宣言された符号化方式の本文だけを検査すれば本文中の `=` を誤爆しない。

### Security — D1316: base64 本文のアルファベット外文字が未検査

- **問題**: base64 本文に `#` 等のアルファベット外文字や行中 `=` が混じると、「読み飛ばす」デコーダと「止める/エラーの」デコーダで復号結果がずれ、検査器と表示側で別の添付内容になる。
- **修正**: `has_invalid_base64_body` — `content-transfer-encoding: base64` のパート本文のみを対象にアルファベット外文字・行中 `=` を検出 (空白と行末パディングは合法) → `Envelope.invalid_base64_body` → render_risks 警告。
- **教訓**: 符号化本文の検査は宣言 CTE に追随する — 全本文を一括で見ると平文パートの記号を誤検出する。

### Security — D1313: 添付名のパストラバーサル成分が未検査

- **問題**: `filename="../../evil.exe"`・`name="C:\x.exe"` 等のディレクトリ成分を含む添付名は、成分を除去するメーラーとそのまま保存するメーラーで保存先がずれる書込み意図の兆候。D1265 は CR/LF・末尾ドット・ホモグリフのみ対象。
- **修正**: `has_traversal_filename` — CT の `name=` と CD の `filename=` 値に `..`・`/`・`\`・ドライブ文字があれば検出 → `Envelope.traversal_filename` → render_risks 警告。
- **教訓**: ファイル名の検査は「表示の偽装」だけでなく「書込み先の指定」も見る — 保存動作は実装差が直接被害になる。

### Security — D1314: 998 バイト超のヘッダ行が未検査

- **問題**: RFC 5322 §2.1.1 の行長上限 (998 バイト) を超えるヘッダ行は、上限で切り詰める実装と全文を読む実装で値がずれる切断差異 (長い件名・宛先・DKIM-Signature に仕込む)。
- **修正**: `has_overlong_header` — 外側ヘッダ部と各 MIME パートのヘッダ run で 998 バイト超の行を検出 (継続行は除外) → `Envelope.overlong_header` → render_risks 警告。
- **教訓**: 規格の数値上限は必ず差異の発生点 — 上限超過の有無は見えているだけで検出の一線。

### Security — D1311: boundary= の空値が未検査

- **問題**: `boundary=""` や `boundary=` 直後に区切りが来る形は区切り文字列が `--` だけに退化する。空境界を「boundary 無し」と扱う実装と「`--` 行すべてを区切りとする」実装でパート構造が完全にずれる (D1281/D1294/D1297 同族の極端形)。
- **修正**: `has_empty_boundary` — Content-Type ヘッダの boundary= 値が (クオート内外問わず) 空なら検出 → `Envelope.empty_boundary` → render_risks 警告。値内部の空白は RFC 合法なので対象外。
- **教訓**: 退化形 (空・極短・既定値) は正規の値域端で見落としやすい — 値の検査は「非空」を前提にしない。

### Security — D1312: MIME-Version の値が 1.0 以外が未検査

- **問題**: D1289 は MIME-Version 欠落のみ検査。値が `2.0` や空欄だと版番号を厳格に見る実装は MIME 構造として扱わず同じ構造差異を生む。
- **修正**: `has_odd_mime_version` — MIME-Version 値が CFWS コメントを除いて `1.0` と一致しなければ検出 → `Envelope.odd_mime_version` → render_risks 警告。
- **教訓**: 「必須フィールドの有無」だけでなく「宣言値が規定値と一致するか」まで見る — 値域のずれも解釈差異を生む。

### Security — D1309: CT/CD パラメータキー重複が未検査

- **問題**: `filename="a.txt"; filename="b.exe"` や `charset=` 重複で先頭/末尾採用が実装間でずれる。D1281 は boundary= のみ対象で他のキーは未カバー。
- **修正**: `has_duplicate_mime_params` — Content-Type/Content-Disposition のパラメータキーを `*` 込みの全体で比較し重複を検出 (RFC 2231 連番 `name*0`/`name*1` は別キーのため誤検出しない) → `Envelope.duplicate_mime_params` → render_risks 警告。
- **教訓**: 特定キーの重複検査は残りのキー全般に一般化する価値がある — 同じ差異の形はどのキーにも現れる。

### Security — D1310: CT の name= ありで Content-Disposition 無しが未検査

- **問題**: 旧来の書法では CT の `name=` が添付ファイル名になるが、添付判定を Content-Disposition のみで行うスキャナは `name=` を見ず拡張子検査を素通りする (表示側は添付として扱う)。
- **修正**: `has_ct_name_no_disposition` — パートのヘッダ run 単位で CT に `name=` があり CD 行が無ければ検出 → `Envelope.ct_name_no_disposition` → render_risks 警告。
- **教訓**: 「判定に使う欄」と「実際に効く欄」が違う旧来の書法は常に差異の温床 — 両方の欄の有無を突き合わせる。

### Security — D1307: ヘッダ部の裸 CR (\r 単独) が未検査

- **問題**: D1298 は CRLF/裸LF の混在のみ検査し、Mac クラシック形式の `\r` 単独行終端は未カバー。`\r\n` と `\n` のみを区切りと見る実装はその行を次行と結合して読み、`\r` を区切る実装は分割する行分割差異。
- **修正**: `has_bare_cr` — ヘッダ部 (`\r\n\r\n`/`\n\n` まで) に `\n` を伴わない `\r` があれば検出 → `Envelope.bare_cr` → render_risks 警告。
- **教訓**: 改行の変種は3種ある (CRLF/LF/CR) — 2種の混在を見ても第3種単独は別検査が要る。

### Security — D1308: mbox 形式 `From ` 行の混入が未検査

- **問題**: メッセージが `From sender@host timestamp` で始まる場合、mbox の格納区切りとして剥がす実装と RFC 5322 の無名ヘッダ行として扱う実装で以降のヘッダ全体の解釈がずれる。
- **修正**: `has_mbox_from_line` — 生メッセージ先頭が `From ` のとき検出 → `Envelope.mbox_from_line` → render_risks 警告 (本文中の `>From` エスケープは対象外)。
- **教訓**: 格納形式と伝送形式の混在は、先頭1行をどう扱うかで全体の構造が割れる。

### Security — D1305: ヘッダ名とコロン間の空白混入が未検査

- **問題**: RFC 5322 は `field-name ":"` の間の空白を許さない。`Subject : x` を「ヘッダ」と見る実装と「無名の行」と見る実装で検査対象ヘッダがずれるヘッダ境界差異。
- **修正**: `has_spaced_header_name` — 外側ヘッダ部と各 MIME パートのヘッダ run で、コロン前が field-name 文字のみかつ末尾空白の行を検出 → `Envelope.spaced_header_name` → render_risks 警告。
- **教訓**: 構文違反の小さな差は「その行をヘッダとして数えるか」という根本的な解釈分岐を生む。

### Security — D1306: 一意ヘッダ重複検査が宛先・日付系を未カバー

- **問題**: D1292 は Subject/From/Message-ID のみ対象だったが、RFC 5322 §3.6 の一意フィールドは他にもある — Date/To/Cc/Bcc/Sender/Reply-To の重複でも先頭/末尾/結合採用が実装間でずれる (表示される送信日や宛先が読み手で違う)。
- **修正**: `has_duplicate_identity_headers` の対象に Date/To/Cc/Bcc/Sender/Reply-To を追加。
- **教訓**: 「同じ種類の違反」は仕様の表を引き当たって全列をカバーする — 部分カバーは残った列が抜け道になる。

### Security — D1303: 生メッセージ内の NUL バイトが未検査

- **問題**: RFC 5322/2045 のメッセージストリームは NUL を含まない (添付も符号化され届く)。生の NUL は C 文字列ベースの実装でそこで文字列を切り詰め、以降の内容が一部の検査器から見えなくなる切断差異。
- **修正**: `has_raw_nul_bytes` — 生メッセージに 0x00 があれば検出 → `Envelope.raw_nul_bytes` → render_risks 警告。
- **教訓**: 「絶対に出てこないはずのバイト」の存在自体が最も安い差異指標 — 仕様の全域禁止をそのまま検査にする。

### Security — D1304: ヘッダ部の非 UTF-8 バイト列が未検査

- **問題**: encoded-word を通さない生の 8bit/不正バイトがヘッダに混ざると、lossy 置換する実装と生バイトを保持する実装で文字列照合の結果がずれる (ドメイン名・件名の中間に不正バイト)。正規 MUA は出さない。
- **修正**: `has_non_utf8_headers` — ヘッダブロック (`\r\n\r\n`/`\n\n` まで) が UTF-8 として不正なら検出 → `Envelope.non_utf8_headers` → render_risks 警告。
- **教訓**: デコード可能性自体が異常信号になる — 「読める」前提を崩す入力はまず兆候として数える。

### Security — D1301: MIME charset= の危険文字コードが未検査

- **問題**: `Content-Type: ...; charset=utf-7` で書かれた本文は ASCII のまま (`+AGQ-` 等) キーワード照合をすり抜け、utf-7 を解釈する表示側でのみ攻撃文字列になる。D978 は `<meta charset>` のみ対象で MIME ヘッダ側は未検査だった。
- **修正**: `has_dangerous_charset` — charset= 値が utf-7/utf7/x-user-defined/utf-16 系等の既知の危険・異常名と一致すると検出 → `Envelope.dangerous_charset` → render_risks 警告。
- **教訓**: 同じ「文字コード指定」の穴が書ける場所は2箇所以上ある (meta と MIME ヘッダ) — 一方を塞いでも他方は別経路として残る。

### Security — D1302: 件名の bidi override/isolate が未検査

- **問題**: 件名の文字種変換検査 (D1276/D1282) に bidi 制御文字 (U+202A–U+202E override、U+2066–U+2069 isolate) が無かった。件名中の RLO で表示順を反転させる trojan-source 系の偽装 (件名列での見せ方改竄)。
- **修正**: `has_suspicious_subject_chars` に `'\u{202A}'..='\u{202E}'` と `'\u{2066}'..='\u{2069}'` を追加。
- **教訓**: 「見え方をずらす文字」は不可視だけでなく表示順を変える系も含む — カテゴリの定義で抜けを防ぐ。

### Security — D1299: アドレスドメインの FQDN 末尾ドットが未検査

- **問題**: `user@example.com.` の末尾ドットは DNS 的に `example.com` と同じホストを指すが、文字列比較でドメイン照合する実装は別ドメインと見る — 送信側が自社ドメイン許可リスト等をすり抜けつつ配送は成立する形。
- **修正**: `has_fqdn_trailing_dot` — From/To/Cc/Reply-To/Return-Path の各 `@` 直後トークンが `.` で終わると検出 → `Envelope.fqdn_trailing_dot` → render_risks 警告。
- **教訓**: 「同じホスト」を指す別表記は照合をすり抜ける — 名前の正規形まで揃えて比較するのが原則、揃えられないなら異形の存在を兆候にする。

### Security — D1300: アドレスヘッダの CFWS コメント内アドレス/URL が未検査

- **問題**: RFC 5322 の括弧コメント `From: ceo@corp.example (billing@victim.example)` に別アドレスや URL を置くと、コメントを差出人として表示するクライアントと無視するクライアントで見えるアイデンティティが分かれる。旧来の `(氏名)` 型は正規用法のため対象外。
- **修正**: `has_address_comment` — 対象ヘッダの `(…)` 内に `@` または `http` を含むと検出 → `Envelope.address_comment` → render_risks 警告。
- **教訓**: コメントのような「仕様上あるが滅多に使わない構文」の中に実体文字列を置くのは典型的な差異工作 — 中身まで読む。

### Security — D1297: 同一 boundary 値の使い回し (境界衝突) が未検査

- **問題**: 外側と入れ子で同じ `boundary=` 値を使うと、`--b--` がどちらのレベルを閉じるか実装ごとに解釈が分かれ、内側コンテンツを外側の一部/別パートとして読み替える境界衝突工作になる。正規 MUA はパートごとにランダムな boundary を生成するため同一値の出現自体が異常。
- **修正**: `has_reused_boundary` — 全 content-type 行の boundary= 値をクオート正規化して数え、同一値が2回以上なら検出 → `Envelope.reused_boundary` → render_risks 警告。
- **教訓**: 識別子の一意性は使い回しでも破られる — 「値が正しい」だけでなく「一意か」も測る。

### Security — D1298: ヘッダ部の CRLF/裸 LF 混在が未検査

- **問題**: RFC 5322 は CRLF を要求するが、ヘッダブロック内に `\r\n` と裸 `\n` が混在すると、裸 `\n` を行終端として認めないパーサは複数ヘッダを1行に結合し、認めるパーサは別々に読む — ヘッダインジェクション系の差異工作 (mixed EOL)。
- **修正**: `has_mixed_line_endings` — ヘッダ部 (最初の `\r\n\r\n`/`\n\n` まで) で CRLF 終端行と裸 LF 終端行の両方があれば検出 → `Envelope.mixed_line_endings` → render_risks 警告。全 CRLF/全 LF の一貫した入力は対象外。
- **教訓**: 区切り文字列自体の一貫性も攻撃面 — 「混在」は仕様差を突く足場。

### Security — D1295: RFC 2231 分割・符号化パラメータの添付名が未検査

- **問題**: `filename*=utf-8''evil.exe` (文字コード符号化) と `filename*0=`/`filename*1=` (分割継続) の RFC 2231/5987 パラメータを再構成しないスキャナは添付名を `filename=` 不在として素通りし、危険拡張子検査が届かない。D1265 はデコード済み名のみ対象で、この経路は未カバーだった。
- **修正**: `has_rfc2231_attachment_params` — content-type/content-disposition 行 (FWS 展開後) で `filename*`/`name*` 系パラメータを検出 → `Envelope.rfc2231_attachment_params` → render_risks 警告。
- **教訓**: 「名前の書き方が複数ある」フィールドは全表記を同一経路に通すか、別表記の存在自体を兆候にする。

### Security — D1296: boundary= のエスケープ/閉じないクオートが未検査

- **問題**: `boundary="a\"b"` の quoted-pair や閉じない `"` は、エスケープ展開するパーサ・素直に閉じ `"` を探すパーサ・パース失敗で boundary 無し扱いのパーサで三者三様の区切りになる (D1281/D1294 と同族の boundary 差異)。
- **修正**: `has_escaped_boundary_quote` — content-type の boundary= クオート値内の `\"`、または行末まで閉じないクオートを検出 → `Envelope.escaped_boundary_quote` → render_risks 警告。
- **教訓**: quoted-string の中身は文字列として見るだけでなく、エスケープ構造の健全性まで測る。

### Security — D1293: multipart コンテナへの非 identity CTE が未検査

- **問題**: `multipart/*` の Content-Transfer-Encoding は RFC 2045 §6.4 で 7bit/8bit/binary 以外が禁止 — `base64`/`quoted-printable` でコンテナ全体を符号化すると「先に decode して分割」する実装と「生のまま分割」する実装で構造が食い違い、内側パートを一方から隠せる。D1285 の重複/不正値検査は値の異常だけで、型との組合せ禁止は未検査だった。
- **修正**: `has_encoded_multipart_container` — ヘッダ run 単位で multipart/* の CT と base64/QP の CTE の共存を検出 (入れ子パートの run も個別評価) → `Envelope.encoded_multipart_container` → render_risks 警告。
- **教訓**: 禁止組合せは値単体ではなく型との対で測る — 正規値でも置く場所が違えば逸脱。

### Security — D1294: boundary= 値の前後空白混入が未検査

- **問題**: RFC 2046 §5.1.1 で boundary は空白で終わってはならない (bcharsnospace 終端)。`boundary="x "` のような前後空白を、trim するパーサとしないパーサで別の区切り文字列になり構造解釈がずれる (mail-parser 系 trailing-whitespace 問題)。
- **修正**: `has_whitespace_boundary` — content-type の boundary= 値 (クオート有無両対応) が trim 前後で変わると検出。値内部の空白は bchars 上合法のため対象外 → `Envelope.whitespace_boundary` → render_risks 警告。
- **教訓**: 「値の体裁」も攻撃面 — 仕様の端処理 (trim 可否) は実装差の温床。

### Security — D1291: Date タイムスタンプの異常が未検査

- **問題**: `Date:` を 48 時間以上の未来日にしたメールは日時ソートで受信トレイ先頭に張り付き続ける既知の戦術で、エポック/1990 年以前の値は RFC 822 普及前の現実離れ値で手作り生成品の兆候 — D1278 の欠落検査は「無い/壊れている」だけで値の異常は未検査だった。
- **修正**: `is_anomalous_date` — Date の UNIX 秒が `now+48h` 超または 1990-01-01 未満なら検出 → `Envelope.anomalous_date` → render_risks 警告。
- **教訓**: 存在の検査の次は値域の検査 — 必須フィールドは「ある」だけでなく「ありえる値か」を測る。

### Security — D1292: 一意ヘッダ (Subject/From/Message-ID) の重複が未検査

- **問題**: RFC 5322 §3.6 で最大1個と定まる `Subject:`/`From:`/`Message-ID:` が複数あると、先頭を採る実装と末尾を採る実装で件名・差出人が別々になり、表示側とフィルタ側で違う値を見せるパーサ差異工作になる (D1281 boundary 重複・D1285 制御ヘッダ重複と同型だが対象フィールドが未カバーだった)。
- **修正**: `has_duplicate_identity_headers` — トップヘッダブロックで `subject:`/`from:`/`message-id:` が2回以上現れると検出 (継続行は行頭名を持たないため誤計数なし、`X-From:` 等は対象外) → `Envelope.duplicate_identity_headers` → render_risks 警告。
- **教訓**: 「最大1個」の制約も攻撃面 — 曖昧さは boundary だけでなく識別ヘッダにもある。

### Security — D1289: MIME-Version 欠落が未検査

- **問題**: `MIME-Version: 1.0` は MIME の宣言 (RFC 2045 §4) — `Content-Type` パラメータや CTE を使いながらこれを欠くメッセージは、MIME として解釈する実装と RFC 5322 素テキストとして解釈する実装で構造が食い違う (D1278 欠落検査の姉妹)。
- **修正**: `has_missing_mime_version` — トップヘッダに `mime-version:` が無く `content-type:` にパラメータ/multipart 指定または CTE/Disposition があると検出 → `Envelope.missing_mime_version` → render_risks 警告。
- **教訓**: 構造を名乗るのに宣言を欠く — 欠落は意味だけでなく存在でも測る。

### Security — D1290: 宣言 boundary の不使用・未終了 multipart が未検査

- **問題**: `boundary=x` を宣言しながら `--x` が一度も現れない、または `--x--` で閉じない multipart は、残り本文の解釈がパーサごとに食い違う (mailsplit の未終了 multipart で外側 boundary が生きたまま残るバグと同型)。
- **修正**: `has_unterminated_multipart` — トップレベル boundary 値を取り `--b`/`--b--` の存在を確認 → `Envelope.unterminated_multipart` → render_risks 警告。
- **教訓**: 「宣言と実際の不一致」は双方の方向で測る — 宣言して使わないも使って閉じないも同じ兆候。

### Security — D1287: 非 multipart Content-Type の bogus boundary= が未検査

- **問題**: `Content-Type: text/plain; boundary=fake` — multipart 以外の型に boundary= があると、それを採用するパーサは本物の外側 boundary を無効化し、後続の実パートをスキャンから隠す (mailsplit AIKIDO-2026-785486 / zone-eu commit 028a6fc — 「boundary 所有権」の取り違え)。
- **修正**: `has_bogus_boundary_param` — `boundary=` を含む `content-type:` 論理行で主型が `multipart/` でなければ検出 → `Envelope.bogus_boundary_param` → render_risks 警告。
- **教訓**: パラメータの「存在」と「型との整合」は別の兆候 — 型に無関係な boundary は差異工作の種。

### Security — D1288: プリアンブル/エピローグ内のパート構造が未検査

- **問題**: 最初の `--boundary` より前、最後の `--boundary--` より後にパート様のヘッダ構造があると、プリアンブル/エピローグを無視するスキャナには見えず MUA は表示する (同じく mailsplit の boundary 所有権バグの系)。
- **修正**: `has_orphaned_part_content` — トップレベル multipart の boundary 値からプリアンブル/エピローグを特定し、その中に `Content-Type:`/`Content-Disposition:`/`Content-Transfer-Encoding:` 行があれば検出 → `Envelope.orphaned_part_content` → render_risks 警告。説明テキストのみのプリアンブルは対象外。
- **教訓**: boundary の外側も内容になりうる — 範囲外にあるヘッダ構造は「見る範囲が違う」差異の兆候。

### Security — D1285: MIME 制御ヘッダの重複・不正 CTE が未検査

- **問題**: 同一パートに `Content-Type:`/`Content-Transfer-Encoding:`/`Content-Disposition:` が複数あると、実装ごとに採用する方が食い違う — noxxi "Dubious MIME" (重複 CTE でスキャナとクライアントが別バイト列を復号) と IETF draft-chen-email-mime-ambiguity-defense-00 (2026-03) が扱う曖昧性工作。`x-uuencode` 等の非標準 CTE 値もフォールバックが実装間で分かれる。
- **修正**: `has_conflicting_mime_headers` — ヘッダブロックごとに制御ヘッダの重複と CTE 値の網羅照合 → `Envelope.conflicting_mime_headers` → render_risks 警告。ブロック先頭から連続する `name:` 行のみ読むため本文誤認なし。
- **教訓**: 曖昧性は値だけでなく「同じ名前の回数」でも測れる — 重複そのものが兆候。

### Security — D1286: インライン uuencode ペイロードが未検査

- **問題**: `begin 644 evil.exe` + `end` の uuencode ブロックは MIME 構造の外 — パート単位で走査する検査を完全に素通りし、自動展開するクライアントでは実行ファイルが現れる (非 MIME スマグリング)。
- **修正**: `has_uuencode_payload` — `begin [0-7]{3} name` / `begin-base64 [0-7]{3} name` の行を先頭 1 MiB で検出 → `Envelope.uuencode_payload` → render_risks 警告。
- **教訓**: MIME の外にもペイロードは置ける — 構造がないこと自体を構造の兆候として数えよ。

### Security — D1283: ヘッダの malformed encoded-word が未検査

- **問題**: `=?UTF-8?B?...` (閉じ `?=` 無し) や `=?utf-8?X?` (不正 encoding) のような RFC 2047 形に合わない encoded-word 断片は、デコードする実装と素通しする実装で表示が食い違う — From/Subject の見た目を攻撃者が制御できるパーサ差異偽装 (CVE-2026-63435 系)。既存の件名/表示名検査はデコード後の文字列を見るため、そもそも形が壊れていることを捉えられなかった。
- **修正**: `has_malformed_encoded_word` — From/To/Cc/Reply-To/Subject を FWS 展開して `=?charset?B|Q?text?=` の形に合わない断片を検出 → `Envelope.malformed_encoded_word` → render_risks 警告。
- **教訓**: 「デコード結果が怪しい」だけでなく「形自体が壊れている」ことも兆候 — 壊れた形はパーサ差異の入口。

### Security — D1284: Content-Location のリモート参照が未検査

- **問題**: MHTML/関連パートで `Content-Location:` が `https://…` を指すと、パート本体は空・無害のまま表示時にリモートフェッチが発生し添付検査を素通りする (MHTML smuggling — Cofense/Trustwave の観測)。`.mht` 拡張子は D166 で既に危険扱いだが、メール本体内の related パートに同じ機構が残っていた。
- **修正**: `has_remote_content_location` — 全文の論理行 (FWS 展開) で `content-location:` ヘッダを探し、値が http(s)/ftp 始まりなら検出 → `Envelope.remote_content_location` → render_risks 警告。`cid:` 等のローカル参照は対象外。
- **教訓**: 「中身が無いパート」は本体ではなく参照を見よ — Content-Location/Content-ID の値そのものがペイロードの配送経路になる。

### Security — D1281: Content-Type の boundary= 重複 (MIME パーサ差異) が未検査

- **問題**: `boundary=safe; boundary=evil` のように `Content-Type:` に複数の `boundary=` があると、先を読む実装と後を読む実装でパート構造が食い違う — ゲートウェイが検査した部分とクライアントが表示する部分が別物になる parser differential (Radboud 大学 MIME 差分ファジング論文 2025、Rack GHSA-vgpv-f759-9wx3 と同型)。既存の `missing_boundary_param` は「無い」場合のみで「重複」は未検査だった。
- **修正**: `has_ambiguous_boundary` (FWS 継続行を展開して論理行単位で boundary= を2個以上カウント) → `Envelope.ambiguous_boundary` → render_risks 警告。
- **教訓**: パラメータ重複は最も安い差異工作 — 「同じ名前が2回」だけで parser differential の兆候になる。

### Security — D1282: 件名の不可視文字検査に soft hyphen 系が抜けていた

- **問題**: SANS ISC 32428 — encoded-word でエンコードされた件名に U+00AD soft hyphen を散りばめ、一覧表示では崩れた見た目・開封時には正規文字として表示・照合は破られる手法。D1276 はタグ文字/ZWJ/装飾字を網羅したが U+00AD・U+2060・U+034F 等の「見えないが制御文字でもない」文字が抜けていた。
- **修正**: `has_suspicious_subject_chars` に SOFT HYPHEN・WORD JOINER・CGJ・ALM・Mongolian Vowel Separator・Hangul filler を追加。
- **教訓**: 不可視文字は範囲ではなく列挙で捉える — 新しい不可視文字が観測されるたびに追加できる網羅リストとして維持せよ。

### Security — D1279: 入れ子メール添付の内側差出人偽装が未可視化

- **問題**: IRONSCALES (2026-01) — 外側メールが空・認証通過・`.eml` 添付の内側 `From:` が受信者の自社経理部門を騙る攻撃。D1250 は「内側は偽装できる」と一般注意喚起するだけで、内側の差出人・件名の値自体は提示されず、受信側ドメインとの一致も未検査だった。
- **修正**: `extract_nested_email_identity` で内側 `From:`/`Subject:` を抽出し `AttachmentScan.inner_sender`/`inner_subject` に格納 → リスク行に可視化。commands.rs で内側差出人ドメインが宛先/自組織ドメインと一致したら render_risks に内部偽装警告。
- **教訓**: 認証の届かない層の自称値は提示するまでが検出 — 「偽装できる」の注意喚起だけでは実際の偽装に気づけない。

### Security — D1280: 空本文 + メール添付のみの相関が未検査

- **問題**: 同 IRONSCALES 事例の外側形状 — 本文が完全に空で `.eml` 添付のみという「外側は無害・内側に偽装を集中」の形は、空本文と添付を別々に見ても兆候にならなかった。
- **修正**: `analysis_text` が空でかつ入れ子メール添付を持つメールに render_risks 注意喚起。
- **教訓**: 「何も書かない」も形状 — 本文の不在と添付種別の組み合わせ自体を兆候として数える。

### Security — D1277: HTML 添付のコメントスタッフィング (走査回避の水増し) が未検査

- **問題**: SANS ISC (2026-07-10) — 資格情報窃取 HTML 添付を大量の `<!-- -->` コメントで水増しし、AI/シグネチャ走査の入力上限を超えさせるキャンペーン。内容解析に新シグナルは不要で「容量の大半がコメント」自体が兆候。
- **修正**: `SmugglingSignal::CommentPadding` を追加 — 16KB 以上でコメントが 50% 超を占める HTML 添付を検出。正規の MSO 条件付きコメント (`<!--[if mso]>`) は比率が低く対象外。
- **教訓**: 水増しは内容ではなく構造で見えている — 「読む部分」が少なすぎる添付は読ませないための形状。

### Security — D1278: Date ヘッダの欠落/不正値が未検査

- **問題**: RFC 5322 で必須の orig date がないか構文解析不能なメール (Outlook が "Date: None" と表示した同 SANS 事例で目視発覚) — 正規の配送メールでは必ず存在し、欠落は手作り生成品の兆候。`Envelope.date` は既に Option だったが解析経路で未使用。
- **修正**: `env.date.is_none()` で render_risks に注意喚起を追加。
- **教訓**: 必須ヘッダの欠落は最も安い兆候 — パーサが Option で返す未使用フィールドを点検せよ。

### Security — D1275: 表示名のホモグリフ/混在スクリプト解析が配線されていなかった

- **問題**: `kaname_bec::idn_homograph::analyze_display_name` は定義済みだったが解析経路に一度も配線されておらず (呼出元ゼロ)、既存の表示名詐称検査は「既知連絡先と一致した場合のみ」発火する設計 — 連絡先にない名前の混在スクリプト (例: `Аdmin` キリル込み) は無条件に素通りだった。
- **修正**: analyze で `env.from[].display_name` に `analyze_display_name` を適用 → render_risks 警告。全角ラテンのみの構成は日本語メールで正規使用のため対象外に限定。
- **教訓**: 作った検査は配線までが実装 — 定義の存在は検出の存在を意味しない。

### Security — D1276: 件名の回避文字 (タグ文字・装飾英数字・ホモグリフ) が未検査

- **問題**: D1257/D1273 の文字種変換検査は本文のみを対象 — 件名はキーワード照合対象でありながら検査の外にあった (`𝐈nvoice` 型の件名偽装・不可視文字分割は素通り)。
- **修正**: `has_suspicious_subject_chars` を追加 — 件名のタグ文字・装飾英数字・ゼロ幅・ラテン混在キリル/ギリシャを検出 → render_risks 注意喚起。日本語件名・全角英数は対象外。
- **教訓**: フィルタ対象の全フィールドに同じ文字種検査を適用せよ — 本文だけ磨くと件名が抜け道になる。

### Security — D1273: 装飾英数字 (囲み文字・太字斜体 Unicode) によるキーワード回避が未検査

- **問題**: フィッシング対策協議会 2026 年報告 — 「〇」「□」等の囲み文字や Mathematical Alphanumeric Symbols (`𝐀𝐦𝐚𝐳𝐨𝐧`) を本文に混ぜると、表示上は通常語でも文字列・正規表現照合が効かない。D1257 の混在検査はキリル/ギリシャのみで装飾英数ブロックは対象外だった。
- **修正**: `ExtractedBodyText.styled_alphanum` を追加 — U+1D400–U+1D7FF・囲みラテン U+24B6–U+24E9・二乗/反転ラテン U+1F130–U+1F189 を検出 → render_risks 注意喚起。全角英数・囲み数字・通常絵文字は対象外。
- **教訓**: 装飾で書かれた字は別の字 — 見た目でなく符号位置で照合せよ。

### Security — D1274: Google 翻訳リダイレクト (translate?u= / translate.goog) が未剥がし

- **問題**: 同上報告 — Google 翻訳 URL をリダイレクト元に使い URL スキャンを回避。`translate.google.com/translate?u=` と `<宛先>.translate.goog` (宛先ドメインがホスト名に埋込) の2形があるが、評判判定は translate.goog (Google) を見て実宛先を見逃す。
- **修正**: `unwrap_protected_url` に2経路追加 — `/translate?` の `u=` パラメータ復元、および `*.translate.goog` ホスト名から宛先ドメインを復元 (`-`→`.`、`--`→`-`) して評価へ回す。
- **教訓**: 信頼ドメインの「中継」は宛先を剥がして評価せよ — 中継者の評判は宛先の無罪を証明しない。

### Security — D1271: 空 Return-Path エンベロープ (Direct Send バイパス) が未検査

- **問題**: ReliaQuest (2026-09) — 空の SMTP エンベロープ差出人 (`Return-Path: <>`) は Microsoft 365 の RejectDirectSend 制御を素通りし、内部ユーザー偽装に使われる。Kaname は不正形 (D281) は見ていたが「空 `<>` + 通常差出人」の組み合わせは未検査だった。
- **修正**: `has_empty_return_path` で `Return-Path:` が `<>`/空白のケースを検出し、From が MAILER-DAEMON/postmaster 系でない場合に render_risks 警告 (正規バウンスは対象外)。
- **教訓**: 認証系ヘッダは「形の正しさ」だけでなく「値の不在」を疑え — 空欄は制御の射程外。

### Security — D1272: Content-Type name= と filename= の不一致が未検査

- **問題**: 同一 MIME パートで `Content-Type: name=` と `Content-Disposition: filename=` が食い違うと、検査側と保存側で別名を使うパーサ差異工作になる (name=safe.pdf で検査通過・filename=evil.exe で保存、の型)。
- **修正**: `has_filename_name_mismatch` でパートヘッダブロック単位に両パラメータを比較 → render_risks 注意喚起。片方のみの指定は対象外。
- **教訓**: 同じ実体を二度名付ける仕組みは不一致を疑え — パーサ差異は常に相対比較で暴く。

### Security — D1269: 送信者ローカル部のゼロ幅/ホモグリフ混入が未検査

- **問題**: IRONSCALES (2026-05) が観測した契約メール偽装は、From ローカル部にキリル文字と U+200D (ZWJ) を混ぜ「contracts」に見えるが文字列照合には一致しないアドレスを使い、SPF/DKIM/DMARC を通過した。Kaname は表示名・ドメインの偽装は見ていたが、ローカル部の文字構成は未検査だった。
- **修正**: `has_suspicious_local_part` を追加 — ローカル部のゼロ幅/書式制御文字 (ZWSP/ZWJ/ZWNBSP/SOFT HYPHEN/タグ文字等) とラテン混在のキリル・ギリシャ文字を検出 → render_risks 警告。全キリル名・日本語名は対象外。
- **教訓**: 名前はラベルではなく文字列そのものを疑え — 見た目が同じでも bytes が違えば照合は破れる。

### Security — D1270: HTML 本文のリモートリソース参照 (トラッキングピクセル) が非報告

- **問題**: 描画層のサニタイズは `<img src="http…">` 等のリモート参照を除去するため実行リスクはないが、「参照が存在したこと」自体は利用者に見えないままだった。開封確認ピクセルはメールボックス生存確認の偵察として観測されている (IRONSCALES 2026-05)。
- **修正**: `ExtractedBodyText.remote_resource` を追加 — `<img src>`/`srcset`/`background`/`poster`/`lowsrc`/`dynsrc`/`<link href>` の http(s) 値と style の `url(http…)` を検出 (`<a href>` 通常リンク・cid:/data: は対象外) → render_risks に注意喚起。
- **教訓**: 中和したものも「あったこと」は報告せよ — 除去と記録は別の責務。

### Security — D1267: 購読型 URI (webcal:/feed:) がリンク評価を素通り

- **問題**: `webcal:`/`feed:`/`feeds:` URI は「開く」ではなく「購読する」— 悪意あるカレンダー購読 (calendar spam キャンペーン) は以後イベント・通知の形でメール検査の外から届き続ける。`extract_urls_from_text` は http(s) のみ抽出するためこの誘導経路は未検査だった。
- **修正**: `has_subscription_uri` を追加し `analyze` で検出 → render_risks に警告 (アプリ起動型 D1262 とは性質が異なるため別検査)。
- **教訓**: ペイロードは一度届くものだけではない — 継続的に届くチャンネルを確立させる URI も誘導経路と数えよ。

### Security — D1268: vCard 添付の外部 URI 参照 (PHOTO/URL 等) が未検査

- **問題**: `.vcf` (RFC 6350) の URI 値プロパティ — `PHOTO`/`LOGO`/`SOUND`/`SOURCE`/`URL`/`GEO`/`IMPP`/`ORG-DIRECTORY` — はインポート・表示時にリモートからフェッチされる。連絡先の体裁で任意 URL を載せられ、ICS の `ATTACH;VALUE=URI` (D1264)・`message/external-body` (D1266) と同型の死角だった。
- **修正**: `detect_vcard_external_refs` を追加し `scan_attachment_bytes` で検査 — URI プロパティの値部が http(s)/ftp で始まる行を警告 (data: inline・CID: 埋め込みは対象外)。
- **教訓**: 「連絡先に見える添付」も外部を引きにいく形を持ち得る — 表示時フェッチの形状は形式を問わず数えよ。

### Security — D1265: 添付ファイル名の異常形状 (制御文字・末尾ドット・ホモグリフ) が未検査

- **問題**: IRONSCALES (2026-04) が観測した nested RFC822 キャンペーンは、添付ファイル名に CR/LF 制御文字を注入し、ツールごとのファイル名終端解釈の差でスキャナと実際の保存名を食い違わせていた。加えて `evil.exe.` のように末尾ピリオド/空白を付けると `ends_with(".exe")` 系の拡張子検査を素通りしつつ Windows は除去して保存するため表示名と実体がずれ、キリル/ギリシャ文字混在のホモグリフ名 (`invoiсe.pdf` — キリル с) も検査されなかった。
- **修正**: `magic_bytes::filename_anomalies` を追加し `scan_attachment_bytes` で検査 (制御文字 C0/C1/DEL、末尾 `.`/` `、ステム内キリル・ギリシャ×ラテン混在)。末尾除去後の名前でも危険拡張子を再評価し、`evil.exe.` は Danger 判定。
- **教訓**: 名前は「表示されるもの」ではなく「保存されるもの」を検査せよ — ツール間の解釈差はそれ自体が攻撃面。

### Security — D1266: 特殊 `message/*` サブタイプ (external-body / partial / delivery-status) が未検査

- **問題**: `message/rfc822` 転送添付には注意喚起があるが (D1250)、同じ死角を作るサブタイプは素通りだった: `message/external-body` は中身を持たず URI で外部参照して表示時にフェッチ (ICS `ATTACH;VALUE=URI` と同型)、`message/partial` はペイロードを複数メッセージに断片化し各片の検査を素通り、`message/delivery-status`/`disposition-notification` は内容を返せないパートとして解析の死角になる (IRONSCALES 2026-04 で delivery-status が検査不能のまま届いた事例)。
- **修正**: `magic_bytes::is_exotic_message_subtype` を追加し `scan_attachment_bytes` で注意喚起 (パラメータ付き宣言も判定)。Caution 級。
- **教訓**: 「中身を持たない/持てない」サブタイプはスキャン不能を前提に兆候として数えよ。

### Security — D1263: 意図的に壊された ICS 構造 (malformed calendar invite) が未検査

- **問題**: Mimecast (2026-06) が観測した 4 千件超の quishing キャンペーンは、.ics 招待を RFC 5545 に違反する形で意図的に壊し、QR 抽出ツールをパース段階で失敗させていた: (a) `BEGIN:VCALENDAR` の前に大量の X- ジャンク行、(b) `X-GENERATION; FUTURE:` 型 — `;` 後のパラメータが `name=value` 形を取らない — の無意味な X- プロパティ行。正当な ICS 生成器はどちらも出力しないが、kaname-render の CalendarGuard は構造異常を一切見ていなかった。
- **修正**: `CalendarRisk::MalformedStructure { leading_lines, malformed_x_props }` を追加し `analyze` で検査 (継続行・正規 X- プロパティは対象外)。Caution 扱いで兆候として報告。
- **教訓**: 「読めないはずの形で届く」こと自体が兆候 — パースに失敗させるための壊れ方は、パースの成否ではなく形の逸脱として数えよ。

### Security — D1264: ICS の ATTACH 外部 URI 参照 (QR 画像配送経路) が未検査

- **問題**: 同キャンペーンは QR 画像を `ATTACH;VALUE=URI:` で外部参照し、カレンダーアプリが招待を表示した時点でリモートからフェッチさせた — スキャン時点で中身を持たないため URL 評価 (SuspiciousUrl) は宛先ドメインが正当なら素通りし、`ENCODING=BASE64` 埋め込み検査 (EmbeddedBinaryAttachment) の対象にもならない。
- **修正**: `CalendarRisk::ExternalAttachUri` を追加し、`VALUE=URI` パラメータまたは値部が http で始まる ATTACH 行を検出 (CID: 埋め込み参照は対象外)。
- **教訓**: 「表示時にフェッチされる参照」はスキャンの外で動く — 中身の評価ができなくても「外部を引きにいく形」自体を数えよ。

### Security — D1260: URL の `@` 混乱・不正ハイフンラベル・ハイフン折りたたみブランドが未検査

- **問題**: SANS ISC (2026-09-24) が観測した URL は 3 つの罠を重ねていた: (a) authority の `YKZjqa7A@` userinfo — ブラウザは黙って捨てるがブロックリストを URL ごとに個別化し、メールアドレスにも見せかける; (b) `gynd--.koncar-hr.com` 型の `-` で終わるラベル — RFC 952/1123 上は不正だが DNS は解決するため、厳密な URL 抽出器・リンクリライタが「不正」と判断してスキャン対象から落とす; (c) パスの `/@victim.example.com` — 最後の `@` で分割する不正パーサには受信者の自社ドメインがホストに見える。`extract_domain` は userinfo を正しく除去するが「含まれていたこと」は報告されず、ラベル形状の検査もなかった。
- **修正**: `evaluate_url_inner` に構造異常チェックを追加 — URL 中の `@`、`-` で始まる/終わるホストラベル、および `-`→`.` 折りたたみで信頼ドメイン構造 (`microsoft-com.evil.example` → `microsoft.com.evil.example`) が浮かぶホストをすべて Suspicious。
- **教訓**: 除去して終わりでは記録が残らない — userinfo は「存在したこと」自体が兆候。形式として「不正だが解決できる」構造はスキャナを黙らせる罠として検査せよ。

### Security — D1261: LinkedIn/YouTube/Meta 上のオープンリダイレクタが unwrap 対象外

- **問題**: `linkedin.com/slink?url=`・`youtube.com/redirect?q=`・`l.facebook.com/l.php?u=` はブランドドメインに寄生して最終宛先を隠すオープンリダイレクト — SafeLinks/URLDefense 等の unwrap (D1249) に収録されていなかった。
- **修正**: `unwrap_protected_url` に 3 ホストのクエリパラメータ剥がしを追加し、内側の宛先を再評価。
- **教訓**: リダイレクタはゲートウェイ製品だけでなく SNS の正当な機能にもある — 宛先がクエリにある限り同じ手続きで剥がせ。

### Security — D1262: アプリ起動型 URI スキーム (ms-msdt:/search-ms:/ms-appinstaller:) が本文検査を素通り

- **問題**: `extract_urls_from_text` は http(s) のみを拾うため、OS のプロトコルハンドラを起動する URI (`ms-msdt:` — Follina/CVE-2022-30190、`search-ms:`、`ms-appinstaller:` — 2023-24 サイドロード悪用、`itms-appss:`) がリンク評価の対象にすらならなかった。
- **修正**: `has_external_protocol_uri` で本文中の悪用実績のあるアプリ起動スキームを検出し `render_risks` 警告。
- **教訓**: 「URL でない URI」も誘導経路 — スキームを抽出条件にしている抽出器は、その外側の OS 起動経路をも列挙せよ。

### Security — D1248: HTML 添付が `HtmlSmugglingDetector` を通っていなかった + ClickFix/FileFix 型のシグナル欠落

- **問題**: `HtmlSmugglingDetector` は `parse()` の **本文** HTML にしか適用されておらず、添付ファイルとして届く `.html`/`.htm` は一切検査されなかった。「添付の HTML をブラウザで開かせる」経路は ClickFix キャンペーン (Microsoft Threat Intelligence, 2025-08) の主要ベクタ — 偽 CAPTCHA 画面が `navigator.clipboard.writeText` でコマンドをクリップボードに書き込み、「Win+R → Ctrl+V → Enter」や「アドレスバーに貼り付け (FileFix, Check Point 2025-07)」と利用者自身に実行させる手口であり、本文をいくら検査しても添付は素通りだった。また検出器自体にも clipboard 書き込み・実行誘導のシグナルが無かった。
- **修正**: `scan_attachment_bytes` に HTML 添付判定を追加 — 拡張子 (`.html`/`.htm`)・宣言 MIME (`text/html`)・中身 (`<html`/`<!doctype html`/`<script`) のいずれかで `HtmlSmugglingDetector.analyze` を走らせ、High/Critical を `is_dangerous` に格上げ。検出器には `SmugglingSignal::ClipboardWrite` (`navigator.clipboard.write*`/`execCommand("copy")` 等) と `SmugglingSignal::RunDialogLure` (Win+R/ファイル名を指定して実行/アドレスバー貼り付け/to verify 等の誘導句) を追加し、**クリップボード書込 × 実行誘導**、または **偽 CAPTCHA × 実行誘導** の組み合わせを Critical とする (単独シグナルは Caution どまりで誤検出を抑止)。Critical 時は ClickFix 型を明示した警告文を返す。
- **教訓**: 脅威情報の収集経路 (本文) と実行経路 (添付→ブラウザ) が違えば、同じ検出器でも片方は素通りする。新しい手口は「どの入口でコードが走るか」で入口を洗い直せ。

### Security — D1249: URL 評価がメールセキュリティゲートウェイの書き換え URL の外側しか見ていなかった

- **問題**: SafeLinks (`*.safelinks.protection.outlook.com/?url=…`)・Proofpoint URLDefense・Mimecast・Barracuda・Cisco Secure Email・Trend Micro ClickTime・Sophos・Websense/Forcepoint 等は宛先 URL を自社ドメインで包む。`quishing::evaluate_url` は外側のドメインを評価するため、(a) 悪意の宛先が「Microsoft のドメイン」に見えて素通りし、(b) 逆に宛先が無害なのに書き換えホストが短縮・不審ドメイン扱いされる — どちらに倒れても宛先が評価されていなかった。
- **修正**: `evaluate_url` はまず `unwrap_protected_url` で包みを剥がしてから内側を再帰評価する (深度上限 2 — SafeLinks が URLDefense を包む二重ラッパに対応、無限再帰は防ぐ)。剥がせる形式: SafeLinks `url=`、URLDefense v1/v2/v3 (公式 `urldecoder.py` のアルゴリズム — v3 の `*`/`**X` トークン置換・単一スラッシュ修復・`-`→`%`,`_`→`/` 変換を含む)、Google `/url?q=`・`/imgres?imgurl=`、Slack `slack-redir.net?url=`、Bing `/ck/a` の `u=a1<base64url>`、Mimecast の `?domain=` (宛先ドメインのみ復元)。復元不能な書き換えホスト (宛先をサーバ側でしか持たないもの: Barracuda/Cisco/Trend Micro/Sophos/Websense/wsed.org/mimecastprotect/avanan 等) は `Suspicious` — 「検証不能な間接参照」として報告。パーセントデコード・urlsafe base64・最小限の HTML アンエスケープは外部クレートを増やさず自前実装。
- **教訓**: 評価対象は「表示されたホスト」ではなく「最終宛先」。間接参照は常に中身を見てから判定し、見えないなら見えないと言え。

### Security — D1250: マクロ有効 Office 形式・代替配送形式・ネストしたメール添付が危険拡張子リストに無かった

- **問題**: 危険拡張子は `.exe`/`.scr`/`.docm` 等を押さえていたが、(a) マクロ有効テンプレート/アドイン系 — `.dotm`/`.xltm`/`.potm`/`.ppsm`/`.sldm`/`.ppam`/`.xlam`/`.xla`/`.xll`/`.xlm`/`.xlsb`/`.docb`/`.vsdm`/`.mpa`/`.accde`、(b) 近年キャンペーンで多用される代替配送形式 — `.one`/`.onepkg` (Qakbot/IcedID 2023)、`.chm`、`.reg`、`.sct`、`.wsc`、`.slk`、`.iqy`、`.website`、`.library-ms`、`.search-ms`、`.settingcontent-ms`、`.theme`、`.mht`/`.mhtml` (CVE-2021-40444)、`.cpl`、`.msc`、`.inf`、`.diagcab` (Follina)、`.xbap`/`.appref-ms` — が抜けていた。また内側の件名・差出人・本文を外側と無関係に偽装できる `.eml`/`.msg` 添付も未検査だった。
- **修正**: `is_dangerous_windows_attachment` に上記拡張子を追加 (`.vhd`/`.vhdx` 系のコンテナ列に続く同じ matches! ディスパッチ)。`.eml`/`.msg`/`message/rfc822`/`application/vnd.ms-outlook` は `is_nested_email_attachment` で識別し、`scan_attachment_bytes` で注意喚起 (実行リスクにはしない — 転送メールの正当利用が多いため)。
- **教訓**: 拡張子リストは Microsoft のマクロブロック対象・観測済みキャンペーンの配送形式を定期輸入する台帳 — 一度作って終わりではない。

### Security — D1251: 「暗号化 ZIP 添付 × 本文のパスワード記載」の相関が未検査だった

- **問題**: Emotet/Qakbot 型の添付回避は、解凍・スキャンできないよう ZIP を暗号化した上でパスワードを本文に書く (Sublime Security の `body_encrypted_zip_password_attachment` 検知ルールと同型)。`AttachmentScan` は ZIP の中身を全く見ていなかったため、暗号化エントリの存在も、本文側の「解凍パスワードは〇〇です」との相関も検出できなかった。
- **修正**: `zip_has_encrypted_entries` (ローカルファイルヘッダの汎用フラグビット 0 を走査、壊れた構造では次の `PK\x03\x04` へ再同期) と `is_zip_file` を `magic_bytes` に追加。`AttachmentScan.is_encrypted` を新設し `scan_attachment_bytes` で設定 + 検査不能の通知を risks に積む (暗号化単体では `is_dangerous` にしない — 正規の機密送付がある)。本文側は `body_mentions_password` (パスワード系 × 解凍・添付系キーワードの共起) で「変更してください」型の通知誤検出を避けつつ、`analyze_raw_email` で暗号化添付 × 本文パスワードの組み合わせを警告する。
- **教訓**: 単体では無害な要素同士でも、組み合わせが攻撃の様式美と一致するなら警告価値がある。相関検出は「添付」と「本文」の両方が見える場所 (analyze_raw_email) に置け。

### Security — D1252: URL を含まず電話番号へのコールバックのみを促すメール (TOAD) が未検査だった

- **問題**: TOAD (Telephone-Oriented Attack Delivery / コールバックフィッシング) は「ご請求の確認はお電話で」と番号への電話だけを促し、悪意リンクを一切含まない — KnowBe4 の観測では番号のみペイロードが前年比 +449%。URL 抽出 → リンク評価の検査経路は URL が無いメールを完全に素通りする。
- **修正**: `analyze_raw_email` に TOAD 検出を追加 — `urls.is_empty()` (URL 不在) × `contains_phone_number` (10 桁以上の数字列、全角・区切り記号対応) × `has_callback_lure` (お電話/サポート/解約/請求/call/helpline/refund 等の誘導文脈) の 3 条件で警告。URL があるメールや誘導文脈の無い番号表記 (署名等) では発火しない設計。
- **教訓**: 「リンクをクリックさせない」は検査回避として有効 — ペイロードがリンクでない手口は専用の条件で捕まえる。

### Security — D1253: PDF 添付の静的検査がゼロだった (急増する PDF キャンペーンへの未対応)

- **問題**: Securelist (2025-10) が報告する通り、PDF 添付は量産・標的型の両方で急増 — QR コード埋め込みで URL を画像に逃がす型と、パスワード保護でゲートウェイ検査を不通にする型が代表的だが、`scan_attachment_bytes` は PDF を中身で一切見ていなかった (危険拡張子にも `.pdf` は当然含まれない)。
- **修正**: `magic_bytes` に PDF 判定 (`is_pdf_file` — 拡張子または `%PDF-` マジック) と非圧縮オブジェクトの名前トークン走査 (`contains_pdf_token` — 後続が ASCII 英字なら別トークンとみなし `/JS` が `/JScript` に誤爆しない) を追加。`/Encrypt` は `is_encrypted` に接続して D1251 の本文パスワード相関に乗せ、`/JavaScript`・`/JS`・`/OpenAction`・`/AA`・`/Launch` は実行リスク (`is_dangerous`)、`/EmbeddedFile`・`/RichMedia`・`/XFA`・`/SubmitForm`・`/ImportData` は注意喚起。オブジェクトストリーム圧縮された PDF では検出できない — ベストエフォートの静的検査。
- **教訓**: 「文書」は安全とみなす拡張子リストの盲点になる。各形式の「実行要素」は形式ごとの台帳で管理せよ。

### Security — D1254: 差出人 == 宛先 (self-addressed) の未検査

- **問題**: Microsoft Security Blog (2025-09) の AI 難読化 SVG フィッシング解析で、From = To とし実標的を BCC に入れる「自己宛て」パターンが観測された。受信者本人の名を騙る形になり内側の本文も自社風に偽装できるが、`Envelope` の `from`/`to` の一致は見ていなかった。
- **修正**: `analyze_raw_email` で `env.to` のいずれかと `env.from` のいずれかが (ASCII 大小無視で) 一致する場合に注意喚起。「自分宛て控え」の正当用途があるため実行リスクではなく警告どまり。
- **教訓**: ヘッダ間の「同じであること」自体が兆候になる — 各ヘッダの単独の正当性だけでなく関係性を見よ。

### Security — D1255: Punycode/Unicode (IDN) ホストが評価されていなかった

- **問題**: `evaluate_url` はドメインの TLD・短縮サービス・既知悪性の判定をしていたが、`xn--` ラベル (Punycode) や非 ASCII を直接含むホストを見ていなかった。ブラウザは `xn--` を Unicode 化して表示するため、ASCII 文字列として読む利用者・スキャナには `paypal.com` ではなく `pаypal.com` 類の別ドメインに見える (UTS#39 の紛らわしい文字 — キリル文字ホモグラフ等)。
- **修正**: 信頼ドメイン判定の直後・短縮 URL 判定の前に、ドメインが `xn--` ラベルを含むか ASCII 外文字を含む場合に `Suspicious` を返す。正規 IDN (日本語ドメイン等) も存在するため Malicious ではなく Suspicious — 「審査してから開け」の水準。
- **教訓**: 表示用にエンコードされた識別子は、エンコード後の形ではなく解釈後の形で評価せよ — Punycode のままでは「人間が読める名」にならない。

### Security — D1256: SVG の非表示要素 (難読化) 未検査 + 注意系リスクが添付結果に現れなかった

- **問題**: Microsoft 脅威情報 (2025-09) の AI 生成難読化 SVG 解析で、`display="none"`/`visibility:hidden`/`opacity:0`/`font-size:0` による invisible elements が名指しされた難読化手段だった — 人間には見えない構造をスキャナにだけ見せる (あるいはその逆)。また `scan_attachment_bytes` の SVG 判定は `!scan.safe_as_attachment` 時のみ risks を積んでおり、実行リスクの無い注意系リスク (ExternalReference 等) は警告なしに捨てられていた。
- **修正**: `SvgRisk::HiddenContent { method }` を追加し 16 パターンの非表示化を検査 (実行リスクではなく回避の兆候として記録 — `has_execution_risk` には入れない)。`scan_attachment_bytes` 側は実行リスクの有無に関わらず `scan.risks` を全て報告に積み、`is_dangerous` の決定は従来どおり `safe_as_attachment` に従う。
- **教訓**: 「危ない要素」だけを拾う設計は「回避の兆候」を落とす — 報告の経路は全リスクを通し、危険度の昇格だけを層別に分けよ。

### Security — D1257: Unicode タグ文字 (ASCII スマグリング) とホモグリフ混在が未検査

- **問題**: Microsoft Security Blog (2026-09-03) が観測した高量キャンペーンで、U+E0000–E007F の不可視タグ文字で `funding` 等の金融ルアー語を分割しキーワードフィルタの語結合を破壊する手法 — AI プロンプト注入由来の ASCII スマグリングがメール回避に転用された。KnowBe4 (2026-06) も不可視ノイズ文字と系統的ホモグリフ置換 (キリル а→a 等) の併用を AI 生成フィッシングの指紋として報告。サニタイザはゼロ幅文字 (U+200B 等) を除去するが、タグ文字は除去も報告もされなかった。
- **修正**: `ExtractedBodyText` に `unicode_tag_chars` (タグブロック含有) と `confusable_script_mix` (1 単語内のラテン×キリル/ギリシャ混在) を追加し `html_to_text` で検出、`render_risks` 兆候報告。キリル/ギリシャのみの単語 (正当な露語・希語文) や CJK×ラテン混在は対象外。
- **教訓**: 除去して終わりでは記録が残らない — 不可視文字は「存在したこと」自体が兆候。語の結合を物理文字で切る手口は、文字の役割 (タグ=注記/書式) を逸脱した使用で捕まえられる。

### Security — D1258: デバイスコード・フローへの誘導 (devicelogin) が未検査

- **問題**: Microsoft (2026-09-22) の EvilTokens 解析 — PhaaS が配布する AiTM フィッシングは受信者を `devicelogin` ページへ誘導しデバイスコードを入力させて OAuth トークンを詐取する。正規のデバイスログインは利用者がデバイス側から開始するものであり、メールで誘導されることはないが、本文中の `devicelogin` 誘導は見ていなかった。
- **修正**: `has_devicelogin_lure` で本文 (抽出 URL 含む) の `devicelogin` 言及を検出し `render_risks` に警告。URL 評価ではドメイン正当 (microsoft.com) でも誘導自体が兆候となる型。
- **教訓**: 正当ドメインへのリンクでも「そのフローがメール経由で始まること自体」が兆候になる — 宛先の評判だけでなく到達手段の意味を見よ。

### Security — D1259: LLM 生成前文の残存 (AI 生成メールのアーティファクト) が未検査

- **問題**: KnowBe4 Threat Lab (2026-06) — AI で量産されたフィッシングの 86% に LLM 由来のアーティファクトが残り、特にモデルが出力冒頭に書く構造案内文 ("Here is the message formatted and divided into sections:") が削除されずに届く実例を観測。人間が書くメール本文の冒頭にこうした前置きは出ないが未検査だった。
- **修正**: `has_llm_preamble` で本文冒頭 400 文字の生成前文パターン (英語 11 種・日本語 3 種) を検出し `render_risks` 兆候報告。冒頭限定で転送・引用での文中出現による誤検出を抑止。
- **教訓**: 生成パイプラインの痕跡は内容の品質と無関係に残る — 「人が書くはずの場所に機械の前置きがある」不整合を数えよ。

### Security — D973: href 値の実体参照・%エンコード・制御空白によるスキャン回避

- **問題**: D961–D972 のスキャンは href 属性値の**生文字列**に対する prefix/ホスト比較だったため、`javascript&colon;x`・`&#106;avascript:x` (実体参照)、`%6aavascript:x` (%エンコード)、`java<TAB>script:x` (タブ/改行/復帰の差し込み — ブラウザは URL 中のこれらを除去して解釈する) の 3 系統の難読化で危険スキーム・IP リテラル・IDN・link_mismatch の各検査をすべてすり抜けられた。実体参照デコーダ自体は存在したが `colon`/`tab`/`newline` の名前実体は未定義だった。
- **修正**: `decoded_url_token` を新設 (実体参照 → %HH 復号 → 制御空白除去 → 小文字化、ブラウザと同順序)。`decode_entities_into` に `colon`/`tab`/`newline` を追加。`for_each_href_value` (D964/969-971 全検査) と `record_link_mismatch` (D162) の評価値を復号後のものに変更。`has_dangerous_scheme_link` を `for_each_href_value` 委譲に単純化。
- **教訓**: 生文字列は見た目の写し — ブラウザが解釈する形で評価せよ。

### Security — D974: HTML 本文の `<script>` 要素が未検査

- **問題**: sanitizer は `<script>` を除去するが、「スクリプト実行意図を含む本文」が送られてきたことの報告がなかった。HTML スマグリングの第 1 段として script ブロック (Blob 構築等) を含める攻撃が多い。正規の配信メールは script を含まない (全クライアントが除去するため ESP が生成しない)。
- **修正**: `script_present` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 実行の意図は実行の前に書かれている — 書き込みを数えろ。

### Security — D975: HTML 本文の `<frame>`/`<frameset>` 要素が未検査

- **問題**: D965 は `<iframe>` のみを対象としており、旧来の `<frame>`/`<frameset>` (クリックジャッキング・リモート認証フォーム表示に同用途) は未検査のままだった。
- **修正**: `frame_present` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 古い枠も枠である — 系譜の残りを数えろ。

### Security — D976: HTML 本文の `<template>` 要素が未検査

- **問題**: `<template>` は描画されない不活性 DOM — HTML スマグリングでペイロード断片 (エンコード済みスクリプト等) を格納する「データ島」の定形だが、除去されても兆候として報告されなかった。
- **修正**: `template_present` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 見えない場所に置かれたものは使うために置かれた — 隠し棚を問え。

### Security — D977: `<a download>` 属性が未検査

- **問題**: `<a href="..." download="name.pdf">` はクリック時に「ファイルを開く」ではなく「ファイルを保存させる」強制誘導 — 誤請求書・マクロ付き文書等のダウンロード実行誘導の定形だが、属性の存在が未報告だった。
- **修正**: `has_tag_attr` 汎用スキャナを新設し `has_ping_attr` を委譲、`download_attr` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 「保存させる」と「見せる」は違う — 着地点を問え。

### Security — D978: `<meta charset>` の危険文字コード指定が未検査

- **問題**: `utf-7` は IE 時代の XSS ベクター (文字コード違いによるスクリプト解釈のすり抜け)、`x-user-defined` は HTML スマグリングでバイナリ難読に使われるエンコーディング。正規メールの charset は MIME ヘッダで決まるため meta での指定自体が稀で、この 2 種は正当な用途を持たないが未検査だった。
- **修正**: `has_meta_dangerous_charset` を新設、`meta_charset_danger` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 文字の解釈自体を仕掛ける手は読み替えの罠 — 解読法を問え。

### Security — D979: href 以外の属性値の危険スキームが未検査

- **問題**: D964 は `href` のみを対象としていたが、`src`/`action`/`formaction`/`background`/`poster`/`dynsrc`/`lowsrc`/`xlink:href`/`data` (object) も URL を指す属性 — `<form action="javascript:...">` や `<img src="data:text/html,...">` のような別経路のペイロード内包・スクリプト実行が生きたままだった。
- **修正**: `tag_attr_value` (属性値の正規抽出: `attr=v`/`attr =v`/`attr = v` 各形式) + `has_dangerous_scheme_attr` を新設、`dangerous_scheme_attr` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 同じ役割の属性を片方だけ守ればもう片方が使われる — 経路を全て数えろ。

### Security — D965: HTML 本文の `<iframe>` 要素が未検査

- **問題**: sanitizer は `<iframe>` を黙って除去するため、メール内に外部コンテンツ枠を埋め込むフィッシング (クリックジャッキング・リモートの認証フォーム表示) は表示側で無害化される一方、「含まれていたこと」自体が誰にも報告されていなかった。正規の配信メールは iframe を使わない (全クライアントが除去するため ESP が生成しない)。
- **修正**: `has_open_tag` で `<iframe` を検出、`ExtractedBodyText.iframe_present` → `render_risks` 兆候報告。
- **教訓**: 見えない枠は罠 — 外部を内側に置く構造を問え。

### Security — D966: HTML 本文の `<svg>`/`<math>` 要素が未検査

- **問題**: svg_guard は添付ファイルの SVG を走査するが、**本文中のインライン `<svg>`/`<math>`** は sanitizer の黙示除去で兆候として残らなかった。`<svg>` は `<script>`/`xlink:href` を内包できる実行可能マークアップ (SVG スマグリングは SVG Guard の対象技術そのもの)、`<math>` も MathML の xlink ベクターを持つ。正規メールはインライン SVG を使わず画像で表す。
- **修正**: `svg_math_present` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 絵に見えて動くものは絵ではない — 実行可能な図形を問え。

### Security — D967: HTML 本文の `<object>`/`<embed>` 要素が未検査

- **問題**: `<object data="...">`/`<embed src="...">` はプラグイン・外部オブジェクト経由でペイロードを埋め込む旧来の定形だが、sanitizer の除去リストに入るだけで兆候として残らなかった。
- **修正**: `object_embed_present` フィールドを追加、`render_risks` 兆候報告。
- **教訓**: 外のものを中に置く口は、使われなくても口 — 存在を数えろ。

### Security — D968: `on*` イベントハンドラ属性 (`onload`/`onerror`/`onclick` 等) が未検査

- **問題**: sanitizer は `on*` 属性を除去するが、「スクリプト実行の意図を持つ属性が送られてきた」ことの報告がなかった。`<img src=x onerror=...>` は画像読み込み失敗をフックにする XSS 系フィッシングの定形。
- **修正**: `has_event_handler_attr` を新設 (全開始タグの内部を走査し `on`+英字+`=` を検出 — コメント・DOCTYPE・閉じタグは対象外、`onclick =` の空白にも対応)、`event_handler_attr` → `render_risks` 兆候報告。
- **教訓**: 「何かが起きたら動け」という予約は意図の表明 — トリガーを数えろ。

### Security — D969: `href` 先の IP リテラル・数値形式ホストが未検査

- **問題**: リンク先が `http://203.0.113.9/` のような IP 直指定の場合、ドメイン評判・ドメイン一致系の検査をすべてすり抜ける。さらにブラウザは dword 十進整数 (`http://2130706433/` = 127.0.0.1)、16 進 (`0x7f000001`)、8 進 (`0177.0.0.1`)、短縮形 (`127.1`) をすべて IP として解決するが、これら数値形式も未検査だった (link_mismatches は「表示テキストが URL 形」の場合のみで、素の IP リンクは通過していた)。IP アドレス含有は古典的フィッシング特徴量のひとつ。
- **修正**: `for_each_href_value` (href 属性値の列挙) + `has_host_flag` + `is_ip_literal_host` を新設 — ドット IPv4・IPv6・dword・hex・octal・短縮形をすべて検出、`ip_literal_href` → `render_risks` 兆候報告。
- **教訓**: 名前を持たない場所は名前の評価を受けない — 数字の住所を問え。

### Security — D970: `href` 先の IDN ホスト (xn-- パニコード/非 ASCII) が未検査

- **問題**: `xn--pple-43d.com` のようなパニコードドメインは IDN ホモグリフ (見た目が紛らわしい別文字のドメイン — Unicode 正規化で apple.com 等に酷似) の定形手段だが、href のホストが `xn--` ラベルまたは非 ASCII 文字を含む場合の兆候報告がなかった。
- **修正**: `is_idn_host` を新設、`idn_href` → `render_risks` 兆候報告。
- **教訓**: 似ているものは同じものではない — 文字の出自を問え。

### Security — D971: `href` 先の `.onion` ドメインが未検査

- **問題**: Tor ネットワーク上の `.onion` ホストへのリンクは匿名化された外部誘導 (資格情報収集・ダークウェブポータル) の経路だが、ホスト接尾辞の検査がなかった。
- **修正**: `onion_href` → `render_risks` 兆候報告。
- **教訓**: 足跡を残さない道は選ぶ理由を問え — 匿名経路を数えろ。

### Security — D972: `<a ping="...">` ハイパーリンク監査属性が未検査

- **問題**: `ping` 属性はクリック時にリンク先とは**別の** URL へ POST 通知を送る — トラッキング・ビーコン経路を仕込めるが、`<a>` タグ内の属性として未検査だった (正規のメール生成系は出力しない)。
- **修正**: `tag_is`/`tag_has_named_attr`/`has_ping_attr` を新設、`ping_attr` → `render_risks` 兆候報告。
- **教訓**: 見えない報告は見えるリンクの陰に置く — 影の通知を問え。

### Fixed — D960: tel: リンク検査が未定義変数 `html_text` を参照し kaname-ui がコンパイル不能

- **問題**: D237 で追加した `if html_text.tel_link` が `analyze_raw_email` に存在しない変数 `html_text` を参照していた — `html_to_text` の抽出結果は `Option<ExtractedBodyText>` の `html_extract` に束縛されているため、kaname-ui はコンパイル不能で tel: 兆候は一度も発火していなかった。依存取得不可環境 (D20) で `cargo check` が走らず、static-check は関数呼出しか検査しない (変数参照は対象外) という二重の穴。
- **修正**: `html_extract.as_ref().is_some_and(|e| e.tel_link)` に修正 — Option 経由で tel: 兆候が実際に発火する経路を復元。
- **教訓**: 束縛を疑え — 「あるはずの名前」は grep 1 回で存在確認できる。

### Security — D961: HTML 本文のフォーム要素 (`<form>`/`<input>` 等) が未検査

- **問題**: sanitizer は `<form>`/`<input>`/`<button>`/`<select>`/`<textarea>` を黙って落とすため、資格情報収集フォームを本文に埋め込むフィッシング (外部サイトへ誘導しない分 URL 評判判定を素通り — 資格情報を求めるフォームの存在は PhishKey (arXiv 2506.21106) 等でもコア特徴) は表示側で無害化される一方、「含まれていたこと」自体を誰も報告していなかった。正規の配信メールはフォームを埋め込まずリンクで Web フォームへ遷移させる。
- **修正**: `has_form_elements` + `has_open_tag` (タグ名の後方区切り確認で `<formula>` 等の前方一致誤検を防止) を新設、`ExtractedBodyText.form_present` → `render_risks` 兆候報告。
- **教訓**: 表示で落とすものは解析で数えろ — 無害化は記録の代替ではない。

### Security — D962: `<meta http-equiv="refresh">` による開封時自動転送が未検査

- **問題**: `content="0;url=..."` の meta refresh は HTML メール・添付 HTML に 0 秒リダイレクトを仕込む定形だが、sanitizer が meta を落とすため解析入力からも消え、自動転送の存在自体が未報告だった。
- **修正**: `has_meta_refresh` を新設 (meta タグ内の `http-equiv`+`refresh` を検査 — `<metadata>` 等の前方一致は除く)、`ExtractedBodyText.meta_refresh` → `render_risks` 兆候報告。
- **教訓**: ユーザーの行為を要しない遷移は自動遷移 — 勝手に動く仕組みを問え。

### Security — D963: `<base>` タグによる相対 URL 解決基準の書き換えが未検査

- **問題**: `<base href>` は相対リンク・相対参照の解決基準 URI を送信側が指定する — `<a href="/login">` をタグを解釈する描画環境では別ドメインへ向かわせる基準 URI 偽装の手段。Kaname の描画は base を除去し相対 URL を解決しないため表示影響はないが、含有自体は兆候として報告されていなかった。
- **修正**: `has_base_tag` を新設、`ExtractedBodyText.base_tag` → `render_risks` 兆候報告。
- **教訓**: 解釈の起点は送り主が決めるものではない — 起点を書くタグを問え。

### Security — D964: `data:`/`javascript:`/`vbscript:`/`file:`/`blob:` スキームのリンクが未検査

- **問題**: 本文中の `href` は http(s) のみを URL 抽出の対象とし、表示側は実行スキームを落とすが、「危険スキームのリンクが送られてきた」ことの報告がなかった。`data:text/html` のペイロード内包 (data: URI フィッシング — Unit 42 等が報告)、`javascript:`/`vbscript:`/`blob:` のスクリプト・生成物実行、`file://\\host\share` UNC 参照による SMB 強制認証 (NTLM ハッシュ送信の定形) がすべて兆候として残らなかった。
- **修正**: `has_dangerous_scheme_link` を新設 (`href=` の属性値先頭でスキーム判定 — 無引用符・大文字・`=` 両側の空白に対応)、`ExtractedBodyText.dangerous_scheme_link` → `render_risks` 兆候報告。
- **教訓**: 値の危険度はプレフィックスで決まる — スキーム名を問え。

### Fixed — D571: 「送信側が自称」系の警告が DMARC 認証済みの普通のメールにも出ていた

- **問題**: 「…を送信側が自称する兆候です」等の警告 (207 件) はヘッダの存在だけで出るため、Gmail (`X-Gm-*`/`X-Google-*`)・Microsoft 365 (`X-Microsoft-Antispam`/`X-Forefront-*`)・GitHub・LinkedIn・Mailchimp・配信サービス共通の `Feedback-ID`/`X-Report-Abuse` 等、送信元の基盤が正規に付けるヘッダでほぼ全ての普通のメールに警告枠が出ていた。自動車印の `x-gm-` (General Motors) は Gmail の `X-Gm-Message-State` と衝突し、Gmail 発の全メールを自動車ブランドの自称と誤判定していた。
- **修正**: From ドメインが DMARC pass のときは、送信側が書いたヘッダの存在だけを根拠とする警告 (`SELF_CLAIM_SUFFIXES` の3文言) を出さない (未認証メールでは従来どおり警告)。自動車印から `x-gm-` を除去。`*_marks` 以外のヘッダ専用検出器4件もヘッダ部のみを受け取るよう変更 (D570 の取りこぼし)。static-check 検査11を一般化、検査12で文言契約・ゲートの存在と位置を強制。回帰テスト5件。
- **付随修正**: `kaname-ui` のテスト 14 箇所が存在しない `r.render_risks` を読んでおり、D160 以降テストビルドがコンパイル不能だったのを `r.body.render_risks` に修正。
- **残課題**: 認証済みの無関係ドメインによる他ブランドヘッダの詰め込みは警告しない、D18 (認証結果ヘッダの信頼) を継承、検出器間の接頭辞重複 30 件、`main` の rustfmt 未適用差分 (詳細: `docs/gap-analysis.md` D571)。

### Security — D782: `X-Gaikou-*`/`X-Ekusuteria-*`/`X-Exteriorworks-*`/`X-Exteriordesign-*` 等の外構・エクステリア印自称が未検査

- **問題**: `X-Gaikou-*`/`X-GaikouYasan-*`/`X-GaikouPro-*`/`X-GaikouTeam-*`/`X-GaikouJP-*`/`X-GaikouSenmon-*`/`X-Ekusuteria-*`/`X-EkusuteriaYasan-*`/`X-EkusuteriaPro-*`/`X-EkusuteriaTeam-*`/`X-EkusuteriaJP-*`/`X-EkusuteriaSenmon-*`/`X-ExteriorworksPros-*`/`X-ExteriorworksTeam-*`/`X-ExteriorworksWorks-*`/`X-ExteriorworksExperts-*`/`X-ExteriorworksSvc-*`/`X-ExteriorworksHQ-*`/`X-ExteriordesignPros-*`/`X-ExteriordesignTeam-*`/`X-ExteriordesignWorks-*`/`X-ExteriordesignExperts-*`/`X-ExteriordesignSvc-*`/`X-ExteriordesignHQ-*` 等 は構機の通知記録 — 送信側が書くことは自称。外構・エクステリア工事の偽装は、見積料・追加費用を装ったなりすましの典型手口。(造園は garden 機、フェンスは fence 機、カーポートは carport 機で検出済み)
- **修正**: `Envelope` に `gaikou_marks` + `has_gaikou_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 構印の自署を問え。

### Security — D783: `X-Jumokusou-*`/`X-Sankotsu-*`/`X-Naturalburial-*`/`X-Seaburial-*`/`X-Treeburial-*` 等の樹木葬・散骨印自称が未検査

- **問題**: `X-Jumokusou-*`/`X-JumokusouYasan-*`/`X-JumokusouPro-*`/`X-JumokusouTeam-*`/`X-JumokusouJP-*`/`X-JumokusouSenmon-*`/`X-Sankotsu-*`/`X-SankotsuYasan-*`/`X-SankotsuPro-*`/`X-SankotsuTeam-*`/`X-SankotsuJP-*`/`X-SankotsuSenmon-*`/`X-NaturalburialPros-*`/`X-NaturalburialTeam-*`/`X-NaturalburialWorks-*`/`X-NaturalburialExperts-*`/`X-NaturalburialSvc-*`/`X-NaturalburialHQ-*`/`X-SeaburialPros-*`/`X-SeaburialTeam-*`/`X-SeaburialWorks-*`/`X-SeaburialExperts-*`/`X-SeaburialSvc-*`/`X-SeaburialHQ-*`/`X-TreeburialPros-*`/`X-TreeburialTeam-*`/`X-TreeburialWorks-*`/`X-TreeburialExperts-*`/`X-TreeburialSvc-*`/`X-TreeburialHQ-*` 等 は散機の通知記録 — 送信側が書くことは自称。樹木葬・散骨の偽装は、永代供養料・管理費を装ったなりすましの典型手口。(霊園は reien 機、墓石は sekihi 機、葬儀は funeral 機で検出済み)
- **修正**: `Envelope` に `jumokusou_marks` + `has_jumokusou_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 散印の自署を問え。

### Security — D784: `X-Jinkoushiba-*`/`X-Shibahari-*`/`X-Artificialturf-*`/`X-Turfinstallation-*` 等の人工芝・芝張り印自称が未検査

- **問題**: `X-Jinkoushiba-*`/`X-JinkoushibaYasan-*`/`X-JinkoushibaPro-*`/`X-JinkoushibaTeam-*`/`X-JinkoushibaJP-*`/`X-JinkoushibaSenmon-*`/`X-Shibahari-*`/`X-ShibahariYasan-*`/`X-ShibahariPro-*`/`X-ShibahariTeam-*`/`X-ShibahariJP-*`/`X-ShibahariSenmon-*`/`X-ArtificialturfPros-*`/`X-ArtificialturfTeam-*`/`X-ArtificialturfWorks-*`/`X-ArtificialturfExperts-*`/`X-ArtificialturfSvc-*`/`X-ArtificialturfHQ-*`/`X-TurfinstallationPros-*`/`X-TurfinstallationTeam-*`/`X-TurfinstallationWorks-*`/`X-TurfinstallationExperts-*`/`X-TurfinstallationSvc-*`/`X-TurfinstallationHQ-*` 等 は芝機の通知記録 — 送信側が書くことは自称。人工芝・芝張り業者の偽装は、材料費・施工費を装ったなりすましの典型手口。(造園は garden 機、芝刈りは lawncare 機で検出済み)
- **修正**: `Envelope` に `jinkoushiba_marks` + `has_jinkoushiba_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 芝印の自署を問え。

### Security — D698: `X-Notary-*`/`X-Notarize-*`/`X-Koushou-*`/`X-Apostille-*`/`X-MobileNotary-*` 等の公証印自称が未検査

- **問題**: `X-Notary-*`/`X-Notarize-*`/`X-NotaryCam-*`/`X-MobileNotary-*`/`X-NotaryPros-*`/`X-NotaryService-*`/`X-NotaryTeam-*`/`X-NotaryWorks-*`/`X-NotaryExperts-*`/`X-NotaryDoctors-*`/`X-NotaryMasters-*`/`X-NotaryForce-*`/`X-NotaryNation-*`/`X-NotaryPublic-*`/`X-NotaryAgent-*`/`X-NotarySigning-*`/`X-LoanSigning-*`/`X-SigningAgent-*`/`X-NotaryNow-*`/`X-NotaryHQ-*`/`X-NotarizePros-*`/`X-Apostille-*`/`X-ApostillePros-*`/`X-ApostilleService-*`、JP は `X-Koushou-*`/`X-KoushouYasan-*`/`X-KoushouPro-*`/`X-KoushouTeam-*`/`X-KoushouGyosha-*`/`X-KoushouSeibi-*`/`X-KoushouKensa-*`/`X-KoushouManten-*`/`X-KoushouNomi-*`/`X-KoushouJP-*`/`X-KoushouSenmon-*`/`X-KoushouMitsumori-*`/`X-KoushouChousa-*`/`X-KoushouTeiki-*`/`X-KoushouShuri-*`/`X-KoushouDoctors-*`/`X-KoushouSagyou-*`/`X-KoushouRescue-*`/`X-KoushouTeikyu-*`/`X-KoushouOrder-*`/`X-KoushouJuu-*`/`X-KoushouBosyuu-*`/`X-NotaryKentei-*`/`X-ApostilleYasan-*`/`X-KoushouKyoku-*` 等 は証機の通知記録 — 送信側が書くことは自称。公証・アポスティーユ・ローン署名代行の偽装は、公証手数料・認証費を装ったなりすましの典型手口。(法律事務所は legal 機、電子署名は esign 機で検出済み)
- **修正**: `Envelope` に `notary_marks` + `has_notary_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 証印の自署を問え。

### Security — D699: `X-TransPerfect-*`/`X-Gengo-*`/`X-Honyaku-*`/`X-TranslationPros-*`/`X-Tsuyaku-*` 等の翻訳印自称が未検査

- **問題**: `X-TransPerfect-*`/`X-Lionbridge-*`/`X-Gengo-*`/`X-Smartcat-*`/`X-Translation-*`/`X-TranslationService-*`/`X-TranslationPros-*`/`X-TranslationTeam-*`/`X-TranslationWorks-*`/`X-TranslationExperts-*`/`X-TranslationDoctors-*`/`X-TranslationMasters-*`/`X-TranslationForce-*`/`X-TranslationNation-*`/`X-TranslatePros-*`/`X-TranslateService-*`/`X-LanguagePros-*`/`X-LanguageService-*`/`X-LanguageTeam-*`/`X-InterpreterPros-*`/`X-InterpreterService-*`/`X-InterpretingPros-*`/`X-TranslationsHQ-*`/`X-LocalizePros-*`/`X-LocizePros-*`、JP は `X-Honyaku-*`/`X-HonyakuSha-*`/`X-HonyakuYasan-*`/`X-HonyakuPro-*`/`X-HonyakuTeam-*`/`X-HonyakuGyosha-*`/`X-HonyakuSeibi-*`/`X-HonyakuKensa-*`/`X-HonyakuManten-*`/`X-HonyakuNomi-*`/`X-HonyakuJP-*`/`X-HonyakuSenmon-*`/`X-HonyakuMitsumori-*`/`X-HonyakuChousa-*`/`X-HonyakuTeiki-*`/`X-HonyakuShuri-*`/`X-HonyakuDoctors-*`/`X-HonyakuSagyou-*`/`X-HonyakuRescue-*`/`X-HonyakuTeikyu-*`/`X-HonyakuOrder-*`/`X-HonyakuJuu-*`/`X-HonyakuBosyuu-*`/`X-Tsuyaku-*`/`X-TsuyakuYasan-*`/`X-TsuyakuDaikou-*`/`X-TsuyakuPro-*` 等 は訳機の通知記録 — 送信側が書くことは自称。翻訳会社・通訳派遣・ローカライズの偽装は、翻訳料金・納品手数料を装ったなりすましの典型手口。(語学学校は school 機、字幕は media 機で検出済み)
- **修正**: `Envelope` に `translation_marks` + `has_translation_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 訳印の自署を問え。

### Security — D700: `X-Courier-*`/`X-BikeCourier-*`/`X-Tatuhai-*`/`X-SameDayCourier-*`/`X-MedicalCourier-*` 等のバイク便印自称が未検査

- **問題**: `X-Courier-*`/`X-CourierPros-*`/`X-CourierService-*`/`X-CourierTeam-*`/`X-CourierWorks-*`/`X-CourierExperts-*`/`X-CourierDoctors-*`/`X-CourierMasters-*`/`X-CourierForce-*`/`X-CourierNation-*`/`X-BikeCourier-*`/`X-BikeBin-*`/`X-BikeMessenger-*`/`X-MessengerPros-*`/`X-MessengerService-*`/`X-MessengerTeam-*`/`X-SameDayCourier-*`/`X-MedicalCourier-*`/`X-LegalCourier-*`/`X-RushCourier-*`/`X-ExpressCourier-*`/`X-LocalCourier-*`/`X-CourierHQ-*`/`X-DeliveryProsTeam-*`、JP は `X-Tatuhai-*`/`X-TatuhaiYasan-*`/`X-TatuhaiPro-*`/`X-TatuhaiTeam-*`/`X-TatuhaiGyosha-*`/`X-TatuhaiSeibi-*`/`X-TatuhaiKensa-*`/`X-TatuhaiManten-*`/`X-TatuhaNomi-*`/`X-TatuhaiJP-*`/`X-TatuhaiSenmon-*`/`X-TatuhaiMitsumori-*`/`X-TatuhaiChousa-*`/`X-TatuhaiTeiki-*`/`X-TatuhaiShuri-*`/`X-TatuhaiDoctors-*`/`X-TatuhaiSagyou-*`/`X-TatuhaiRescue-*`/`X-TatuhaiTeikyu-*`/`X-TatuhaiOrder-*`/`X-TatuhaiJuu-*`/`X-TatuhaiBosyuu-*`/`X-BikeBinYasan-*`/`X-Sokuhai-*`/`X-SokuhaiYasan-*` 等 は配機の通知記録 — 送信側が書くことは自称。バイク便・当日便・医療配送の偽装は、配送料金・運送保険を装ったなりすましの典型手口。(宅配は shipping 機、引越は moving 機、バイク販売は cartrade 機で検出済み)
- **修正**: `Envelope` に `courier_marks` + `has_courier_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 配印の自署を問え。

### Security — D611: `X-UCan-*`/`X-TACShool-*`/`X-OharaSchool-*` 等の資格スクール・通信講座印自称が未検査

- **問題**: `X-UCan-*` (ユーキャン)、`X-TACShool-*` (TAC)、`X-OharaSchool-*` (大原)、`X-LECShikaku-*`/`X-Creair-*`/`X-Foresight-*`/`X-Studing-*`/`X-Agaroot-*`/`X-HumanAcademy-*`/`X-ShikakuGetto-*`/`X-BokiSchool-*`/`X-TakkenSchool-*`/`X-SharoshiSchool-*`/`X-GyoseiSchool-*`/`X-ShihoshoshiSchool-*`/`X-FPSchool-*`/`X-ItPassport-*`/`X-ShikakuTaizen-*`/`X-ShikakuDaigaku-*`/`X-ShikakuChannel-*`/`X-ShikakuKing-*`/`X-ShikakuNavi-*`/`X-ManseiShikaku-*`/`X-ShikakuMaster-*`/`X-SomuKentei-*`/`X-BusinessKentei-*`/`X-MosKentei-*`/`X-ToeicSchool-*`/`X-EikenKentei-*`/`X-Kanken-*`/`X-Suuken-*`/`X-ZenkenKentei-*`/`X-HokenKentei-*`/`X-OfficeKentei-*`/`X-WebDesignKentei-*`/`X-ColorKentei-*`/`X-FashionKentei-*`/`X-FoodKentei-*`/`X-SakeKentei-*`/`X-WineKentei-*`/`X-CoffeeKentei-*`/`X-TeaKentei-*`/`X-FortuneKentei-*`/`X-PetKentei-*`/`X-NailKentei-*`/`X-CleaningKentei-*`/`X-StorageKentei-*`/`X-HealthKentei-*`/`X-MentalKentei-*`/`X-WordKentei-*`/`X-EnglishKentei-*`/`X-ItKentei-*`/`X-StatKentei-*`/`X-GyoumuKentei-*`/`X-LegalKentei-*`/`X-KaigoKentei-*`/`X-IryoKentei-*`/`X-KangoKentei-*` 等 は検機の通知記録 — 送信側が書くことは自称。合格発表・教材費・受講料の偽装は資格取得詐欺の典型手口。(塾・予備校機は D605、学習教材機は D532)
- **修正**: `Envelope` に `license_marks` + `has_license_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 検印の自署を問え。

### Security — D612: `X-RyugakuJournal-*`/`X-SeikoRyugaku-*`/`X-Smaryu-*` 等の留学・語学スクール印自称が未検査

- **問題**: `X-RyugakuJournal-*` (留学ジャーナル)、`X-SeikoRyugaku-*` (成功する留学)、`X-Smaryu-*` (スマ留)、`X-RyugakuJohokan-*`/`X-YumekanaRyugaku-*`/`X-WISHRyugaku-*`/`X-EFRyugaku-*`/`X-ILACRyugaku-*`/`X-RyugakuNavi-*`/`X-RyugakuCompass-*`/`X-StudyInJapan-*`/`X-StudyAbroad-*`/`X-AbroadNavi-*`/`X-KaigaiRyugaku-*`/`X-RyugakuHoken-*`/`X-RyugakuCenter-*`/`X-GlobalStudy-*`/`X-LanguageSchool-*`/`X-GogakuSchool-*`/`X-BerkeleyRyugaku-*`/`X-UCLARyugaku-*`/`X-HarvardRyugaku-*`/`X-OxfordRyugaku-*`/`X-CambridgeRyugaku-*`/`X-SydneyRyugaku-*`/`X-MelbourneRyugaku-*`/`X-TorontoRyugaku-*`/`X-VancouverRyugaku-*`/`X-LondonRyugaku-*`/`X-ParisRyugaku-*`/`X-SeoulRyugaku-*`/`X-TaipeiRyugaku-*`/`X-ManilaRyugaku-*`/`X-CebuRyugaku-*`/`X-BangkokRyugaku-*`/`X-AucklandRyugaku-*`/`X-MaltaRyugaku-*`/`X-HawaiiRyugaku-*`/`X-GuamRyugaku-*`/`X-ChinaRyugaku-*`/`X-EuropeRyugaku-*`/`X-AmericaRyugaku-*`/`X-AustraliaRyugaku-*`/`X-CanadaRyugaku-*` 等 は留機の通知記録 — 送信側が書くことは自称。留学費用・ビザ申請・ホームステイ斡旋の偽装は留学詐欺の典型手口。(英会話機は既存族、旅行代理店は D573)
- **修正**: `Envelope` に `abroad_marks` + `has_abroad_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 留印の自署を問え。

### Security — D613: `X-Makita-*`/`X-HiKOKI-*`/`X-TruscoNakayama-*` 等の電動工具・DIY印自称が未検査

- **問題**: `X-Makita-*` (マキタ)、`X-HiKOKI-*` (HiKOKI)、`X-TruscoNakayama-*` (トラスコ中山)、`X-BoschTools-*`/`X-DeWalt-*`/`X-MilwaukeeTool-*`/`X-RyobiTools-*`/`X-Earthman-*`/`X-Einhell-*`/`X-BlackDeckerTool-*`/`X-KainzDIY-*`/`X-KonanPro-*`/`X-VivaHomeDIY-*`/`X-PowerKomeri-*`/`X-KeiyoDIY-*`/`X-Nafco-*`/`X-Homac-*`/`X-Shimachu-*`/`X-SankyuTool-*`/`X-TodaiTool-*`/`X-Sk11Tool-*`/`X-ToneTool-*`/`X-KTCtool-*`/`X-Nepros-*`/`X-SnapOn-*`/`X-WeraTools-*`/`X-Vessel-*`/`X-EngineerTools-*`/`X-HozanTool-*`/`X-GootSolder-*`/`X-Hakko-*`/`X-WellerTool-*`/`X-Nichigoh-*`/`X-MonotaROTool-*`/`X-MisumiTool-*`/`X-Ichinen-*`/`X-SangyoTool-*`/`X-SudoTool-*`/`X-YamawaTool-*`/`X-NachitTool-*`/`X-OSGTool-*`/`X-MitsubishiTool-*`/`X-KyoceraTool-*`/`X-Tungaloy-*`/`X-IscarTool-*`/`X-SandvikTool-*`/`X-Kennametal-*`/`X-DijetTool-*`/`X-NtkTool-*`/`X-BigDaishowa-*`/`X-Nikkentool-*`/`X-RegoTool-*` 等 は具機の通知記録 — 送信側が書くことは自称。工具セット特価・在庫処分・会員価格の偽装は工具詐欺の典型手口。(ワークマン・DCM・コメリは既存族、建機は D538)
- **修正**: `Envelope` に `diytool_marks` + `has_diytool_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 具印の自署を問え。

### Security — D608: `X-Musee-*`/`X-TBC-*`/`X-Kireimo-*` 等のエステ・脱毛・美容クリニック印自称が未検査

- **問題**: `X-Musee-*` (ミュゼ)、`X-TBC-*` (TBC)、`X-Kireimo-*` (キレイモ)、`X-Erucenne-*`/`X-SlimBeauty-*`/`X-TakanoYuri-*`/`X-Mispa-*`/`X-DandyHouse-*`/`X-MensTBC-*`/`X-GorillaClinic-*`/`X-ShonanHiyou-*`/`X-ShinagawaHiyou-*`/`X-Joumoto-*`/`X-Takasu-*`/`X-RizeClinic-*`/`X-AliciaClinic-*`/`X-Strash-*`/`X-C3Esthe-*`/`X-GinzaCalla-*`/`X-Koihada-*`/`X-Lacoco-*`/`X-Eminal-*`/`X-JibunClinic-*`/`X-FureaClinic-*`/`X-SBCShonan-*`/`X-TokyoBiyo-*`/`X-HifuKa-*`/`X-BiyoIin-*`/`X-MedicalEpilation-*`/`X-DatsumouSalon-*`/`X-LaserHair-*`/`X-KireiClinic-*`/`X-BiyoClinic-*`/`X-EstheSalon-*`/`X-EstheNavi-*`/`X-SalonNavi-*`/`X-YaseSalon-*`/`X-DietSalon-*`/`X-FacialSalon-*`/`X-BridalEsthe-*`/`X-MensEsthe-*`/`X-LadiesEsthe-*`/`X-EstheClinic-*` 等 は嬢機の通知記録 — 送信側が書くことは自称。契約更新・回数券残・キャンペーンの偽装はエステ詐欺の典型手口。(美容・コスメ機は D531、リラク機は D594)
- **修正**: `Envelope` に `esthe_marks` + `has_esthe_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 嬢印の自署を問え。

### Security — D609: `X-BikeO-*`/`X-Harley-*`/`X-Ducati-*` 等のバイク・二輪印自称が未検査

- **問題**: `X-BikeO-*` (バイク王)、`X-Harley-*` (Harley)、`X-Ducati-*` (Ducati)、`X-RedBaronMoto-*`/`X-NirinKan-*`/`X-BikeKan-*`/`X-HondaBike-*`/`X-KawasakiBike-*`/`X-YamahaBike-*`/`X-SuzukiBike-*`/`X-BMWMoto-*`/`X-KTMMoto-*`/`X-TriumphMoto-*`/`X-Aprilia-*`/`X-MVAgusta-*`/`X-RoyalEnfield-*`/`X-Bimota-*`/`X-HusqvarnaMoto-*`/`X-Vespa-*`/`X-Piaggio-*`/`X-Adiva-*`/`X-RideZ-*`/`X-MotorcycleShop-*`/`X-BikeShop-*`/`X-NirinSha-*`/`X-MotoTouring-*`/`X-MotoCamp-*`/`X-MotoPark-*`/`X-HelmetShop-*`/`X-Arai-*`/`X-Shoei-*`/`X-OgkKabuto-*`/`X-WinsHelmet-*`/`X-Komine-*`/`X-RSTaichi-*`/`X-Hyod-*`/`X-Kushitani-*`/`X-PowerAge-*`/`X-Marushin-*`/`X-DaytonaBike-*`/`X-KijimaParts-*`/`X-TanaxShokai-*`/`X-DRCMoto-*`/`X-EnduranceMoto-*`/`X-WebikeNews-*`/`X-MotoRaku-*`/`X-MotoAuction-*`/`X-BikeKing-*`/`X-BikeMarche-*`/`X-MotoNavi-*`/`X-BikeNavi-*` 等 は騎機の通知記録 — 送信側が書くことは自称。買取査定・ツーリング案内・車検満了の偽装はライダー狙い詐欺の典型手口。(四輪・車買取は D521/D572、自転車は D577)
- **修正**: `Envelope` に `bike_marks` + `has_bike_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 騎印の自署を問え。

### Security — D610: `X-Fender-*`/`X-Gibson-*`/`X-IkebeGakki-*` 等の楽器・DTM印自称が未検査

- **問題**: `X-Fender-*` (Fender)、`X-Gibson-*` (Gibson)、`X-IkebeGakki-*` (イケベ)、`X-Ibanez-*`/`X-ESPGuitars-*`/`X-Takamine-*`/`X-MartinGuitar-*`/`X-TaylorGuitar-*`/`X-PRSGuitars-*`/`X-MoonGuitar-*`/`X-GrecoGuitars-*`/`X-TokaiGuitars-*`/`X-FujigenGuitar-*`/`X-MomoseGuitars-*`/`X-SugiGuitars-*`/`X-MikiGakki-*`/`X-YamanoGakki-*`/`X-KurosawaGakki-*`/`X-IshibashiGakki-*`/`X-OchanomizuGakki-*`/`X-SoundMesse-*`/`X-DrSound-*`/`X-BeatKinosato-*`/`X-WatanabeGakki-*`/`X-SeasideGakki-*`/`X-EgawaGakki-*`/`X-YamahaGakki-*`/`X-KawaiGakki-*`/`X-MatsumotoGakki-*`/`X-OngakuKan-*`/`X-GakkiCenter-*`/`X-GakkiNavi-*`/`X-GuitarPlanet-*`/`X-BassCellar-*`/`X-DrumStation-*`/`X-DrummerParadise-*`/`X-PianoPlaza-*`/`X-PianoShop-*`/`X-KeyboardShop-*`/`X-SynthShop-*`/`X-DTMStation-*`/`X-DTMNavi-*`/`X-RecGakki-*`/`X-StudioGakki-*`/`X-BandGakki-*`/`X-ViolinShop-*`/`X-BrassShop-*`/`X-TrumpetShop-*`/`X-SaxShop-*`/`X-ClarinetShop-*`/`X-FluteShop-*`/`X-DrumShop-*`/`X-PercussionShop-*`/`X-ElectricGuitar-*`/`X-BassGuitar-*`/`X-UkuleleShop-*` 等 は弦機の通知記録 — 送信側が書くことは自称。中古入荷・限定品・展示セールの偽装は楽器詐欺の典型手口。(島村楽器・KORG・Roland・YAMAHA は既存族、音楽制作ソフトは D497)
- **修正**: `Envelope` に `instrument_marks` + `has_instrument_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 弦印の自署を問え。

### Security — D605: `X-YotsuyaOhtsuka-*`/`X-Eikoh-*`/`X-Nichinoken-*` 等の学習塾・予備校印自称が未検査

- **問題**: `X-YotsuyaOhtsuka-*` (四谷大塚)、`X-Eikoh-*` (栄光)、`X-Nichinoken-*` (日能研)、`X-Meikoh-*`/`X-TryJyuku-*`/`X-WasedaAcademy-*`/`X-Sapix-*`/`X-Ichishin-*`/`X-Rinkai-*`/`X-Shuei-*`/`X-Surara-*`/`X-ZKai-*`/`X-Hamagakuen-*`/`X-NozomiGakuen-*`/`X-Tetsuryokukai-*`/`X-YoyogiSeminar-*`/`X-EnaJyuku-*`/`X-IttoJyuku-*`/`X-Jukucho-*`/`X-Jyukunavi-*`/`X-ScolaJyuku-*`/`X-DrSeminar-*`/`X-KobetsuShido-*`/`X-Katekyo-*`/`X-HomeTeacher-*`/`X-MeikoGijuku-*`/`X-AsahiJyuku-*`/`X-Jishin-*`/`X-Jyuken-*`/`X-Nyushi-*`/`X-GakushuJyuku-*`/`X-OnlineJyuku-*`/`X-SwimSchool-*`/`X-BalletSchool-*` 等 は塾機の通知記録 — 送信側が書くことは自称。入塾案内・講習費・模試結果の偽装は保護者狙い詐欺の典型手口。(河合塾・駿台・東進・武田塾・ベネッセ・進研ゼミは既存族)
- **修正**: `Envelope` に `jyuku_marks` + `has_jyuku_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 塾印の自署を問え。

### Security — D606: `X-Kokuyo-*`/`X-Pentel-*`/`X-MitsubishiPencil-*` 等の文房具・画材印自称が未検査

- **問題**: `X-Kokuyo-*` (コクヨ)、`X-Pentel-*` (ぺんてる)、`X-MitsubishiPencil-*` (三菱鉛筆)、`X-PlusStationery-*`/`X-SakuraCraypas-*`/`X-PilotPen-*`/`X-Tombow-*`/`X-Staedtler-*`/`X-FaberCastell-*`/`X-HiTecC-*`/`X-Frixion-*`/`X-KuruToga-*`/`X-Emott-*`/`X-Shachihata-*`/`X-Hobonichi-*`/`X-HighTide-*`/`X-Kuretake-*`/`X-Ochibi-*`/`X-Sekaido-*`/`X-KingJim-*`/`X-Tanosee-*`/`X-CampusNote-*`/`X-DotLiner-*`/`X-Sarasa-*`/`X-Jetstream-*`/`X-Energel-*`/`X-Acroball-*`/`X-DelGuard-*`/`X-DrGrip-*`/`X-MonoEraser-*`/`X-TapeGlue-*`/`X-Norino-*`/`X-LooseLeaf-*`/`X-ClearFile-*`/`X-RingFile-*`/`X-PenCase-*`/`X-CuttingMat-*`/`X-CardFile-*` 等 は筆機の通知記録 — 送信側が書くことは自称。大量発注・見積・請求の偽装は文具調達担当者狙い詐欺の典型手口。(ZEBRA・ロフト・丸善・ミドリは既存族)
- **修正**: `Envelope` に `stationery_marks` + `has_stationery_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 筆印の自署を問え。

### Security — D607: `X-Zaim-*`/`X-WealthNavi-*`/`X-MoneyTree-*` 等の家計簿・資産管理アプリ印自称が未検査

- **問題**: `X-Zaim-*` (Zaim)、`X-WealthNavi-*` (WealthNavi)、`X-MoneyTree-*` (Moneytree)、`X-Kakebo-*`/`X-OsushiKakeibo-*`/`X-Gridy-*`/`X-Kaneyo-*`/`X-Osarafu-*`/`X-DrWallet-*`/`X-MoneyReco-*`/`X-Kakeico-*`/`X-MoneySquare-*`/`X-Kakeibon-*`/`X-Folio-*`/`X-Theo-*`/`X-RoboPro-*`/`X-WealthAdvisor-*`/`X-PayPayAssets-*`/`X-SBIWealth-*`/`X-RakutenToushi-*`/`X-TsumitateNavi-*`/`X-NISA-*`/`X-IDeCo-*`/`X-AssetView-*`/`X-PortfolioView-*`/`X-HouseholdBook-*`/`X-BudgetBook-*`/`X-ExpenseNote-*`/`X-SpendingTracker-*`/`X-BudgetPlanner-*`/`X-SavingGoal-*`/`X-MoneyDiary-*`/`X-ShisanKanri-*`/`X-KakeiPro-*`/`X-MoneyLog-*`/`X-KakeiboApp-*`/`X-BokinApp-*`/`X-ChokinApp-*`/`X-TsumitateApp-*`/`X-ToushiApp-*`/`X-PointAssets-*`/`X-ReciptScan-*`/`X-ReciptOCR-*`/`X-SeikyuKanri-*`/`X-ShiharaiKanri-*`/`X-KakeiReport-*`/`X-BudgetReport-*`/`X-AssetReport-*`/`X-FinReport-*` 等 は簿機の通知記録 — 送信側が書くことは自称。家計簿連携切れ・資産残高アラートの偽装は金融アプリ詐欺の典型手口。(MoneyForward・ラクマ・銀行機は既存族/D514/D554)
- **修正**: `Envelope` に `budgetapp_marks` + `has_budgetapp_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 簿印の自署を問え。

### Security — D602: `X-Caldo-*`/`X-ZenPlace-*`/`X-Loive-*` 等のヨガ・ピラティス印自称が未検査

- **問題**: `X-Caldo-*` (カルド)、`X-ZenPlace-*` (zen place)、`X-Loive-*` (ロイブ)、`X-HotYoga-*`/`X-StudioYoga-*`/`X-YogaWorks-*`/`X-YogaJaya-*`/`X-Bikram-*`/`X-YogaLab-*`/`X-BestBody-*`/`X-PilatesK-*`/`X-UrbanPilates-*`/`X-StudioPilates-*`/`X-NamasteYoga-*`/`X-YogaRoom-*`/`X-BeyondYoga-*`/`X-AloMoves-*`/`X-GloYoga-*`/`X-YogaInternational-*`/`X-CorePowerYoga-*`/`X-PureYoga-*`/`X-YogaSix-*`/`X-HotYogaClub-*`/`X-SunYoga-*`/`X-MoonYoga-*`/`X-YinYoga-*`/`X-KundaliniYoga-*`/`X-AshtangaYoga-*`/`X-HathaYoga-*`/`X-IyengarYoga-*`/`X-RestorativeYoga-*`/`X-VinyasaYoga-*`/`X-AerialYoga-*`/`X-MamaYoga-*`/`X-MaternityYoga-*`/`X-SeniorYoga-*`/`X-KidsYoga-*`/`X-OnlineYoga-*`/`X-HomeYoga-*`/`X-YogaLesson-*`/`X-YogaInstructor-*`/`X-YogaSchool-*`/`X-YogaFesta-*` 等 は瑜機の通知記録 — 送信側が書くことは自称。月額会費・体験レッスン・回数券の偽装はヨガ詐欺の典型手口。(フィットネスジム機は D530、LAVA は既存族)
- **修正**: `Envelope` に `yoga_marks` + `has_yoga_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 瑜印の自署を問え。

### Security — D603: `X-ShogiWars-*`/`X-ShogiClub24-*`/`X-NihonKiin-*` 等の将棋・囲碁・ボードゲーム印自称が未検査

- **問題**: `X-ShogiWars-*` (将棋ウォーズ)、`X-ShogiClub24-*` (将棋倶楽部24)、`X-NihonKiin-*` (日本棋院)、`X-IgoNet-*`/`X-KansaiKiin-*`/`X-81Dojo-*`/`X-Pandanet-*`/`X-KGSGo-*`/`X-OGSGo-*`/`X-FoxGo-*`/`X-TygemGo-*`/`X-ShogiQuest-*`/`X-ShogiDojo-*`/`X-IgoQuest-*`/`X-GoQuest-*`/`X-Goseki-*`/`X-ShogiTaikai-*`/`X-ShogiKentei-*`/`X-ShogiAcademy-*`/`X-BoardGameCafe-*`/`X-BGG-*`/`X-YellowSubmarine-*`/`X-JellyJellyCafe-*`/`X-Catan-*`/`X-Meeple-*`/`X-Dominion-*`/`X-Carcassonne-*`/`X-TicketToRide-*`/`X-Pandemic-*`/`X-Azul-*`/`X-Splendor-*`/`X-7Wonders-*`/`X-Agricola-*`/`X-Terraforming-*`/`X-Gloomhaven-*`/`X-Wingspan-*`/`X-RootGame-*`/`X-Scythe-*`/`X-TwilightStruggle-*`/`X-BrassBirmingham-*`/`X-ArkNova-*`/`X-TCGCafe-*` 等 は棋機の通知記録 — 送信側が書くことは自称。対局料・大会費・棋書購入の偽装は将棋・囲碁愛好家狙い詐欺の典型手口。(TCG・遊戯王・ポケカは D558)
- **修正**: `Envelope` に `boardgame_marks` + `has_boardgame_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 棋印の自署を問え。

### Security — D604: `X-Photoback-*`/`X-Albus-*`/`X-Dotti-*` 等の写真プリント・フォトブック印自称が未検査

- **問題**: `X-Photoback-*` (Photoback)、`X-Albus-*` (ALBUS)、`X-Dotti-*` (ドッティ)、`X-Asukabook-*`/`X-DreamPages-*`/`X-PhotobookJP-*`/`X-Caine-*`/`X-Kinekawa-*`/`X-Fuful-*`/`X-PhotoRevo-*`/`X-Picpic-*`/`X-Photocopi-*`/`X-MyPhotobook-*`/`X-FamilyAlbum-*`/`X-Memolee-*`/`X-PhotobookStore-*`/`X-Pripri-*`/`X-AlbumCube-*`/`X-PhotoPri-*`/`X-OmoideBako-*`/`X-PrintStudio-*`/`X-FujifilmAlbum-*`/`X-ShinyPrint-*`/`X-FotoKite-*`/`X-PhotoPiece-*`/`X-IrodoriPrint-*`/`X-Tanreisha-*`/`X-FilmScan-*`/`X-NegaScan-*`/`X-PhotoLab-*`/`X-FilmDev-*`/`X-PrintPhoto-*`/`X-HappyPrint-*`/`X-SmilePrint-*`/`X-OmoidePrint-*`/`X-KidsPhoto-*`/`X-BabyPhoto-*`/`X-WeddingPhoto-*`/`X-SchoolPhoto-*`/`X-AlbumShare-*`/`X-PhotoShare-*`/`X-MemorialPhoto-*`/`X-SnapshotPhoto-*`/`X-PhotoCalendar-*`/`X-PhotoGift-*`/`X-PhotoMug-*`/`X-PhotoCanvas-*`/`X-PhotoPanel-*`/`X-PhotoFrame-*`/`X-PhotoCard-*`/`X-PhotoSeal-*`/`X-PhotoSticker-*`/`X-PhotoKeychain-*` 等 は像機の通知記録 — 送信側が書くことは自称。印刷完了・納期遅延・データ破損の偽装は写真注文詐欺の典型手口。(印刷通販機は D590、しまうまプリント・みてねは既存族)
- **修正**: `Envelope` に `photoprint_marks` + `has_photoprint_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 像印の自署を問え。

### Security — D599: `X-PGM-*`/`X-Accordia-*`/`X-GolfNow-*` 等のゴルフ場・練習場印自称が未検査

- **問題**: `X-PGM-*` (PGM)、`X-Accordia-*` (アコーディア)、`X-GolfNow-*` (GolfNow)、`X-TaiheiyoClub-*`/`X-Tokow-*`/`X-JumboGolf-*`/`X-TsuruyaGolf-*`/`X-NikiGolf-*`/`X-Golf5-*`/`X-AlpenGolf-*`/`X-MizunoGolf-*`/`X-HonmaGolf-*`/`X-BridgestoneGolf-*`/`X-VictoriaGolf-*`/`X-PrestigeGC-*`/`X-TomeiCC-*`/`X-TotsukaCC-*`/`X-NagoyaGC-*`/`X-ChibaGC-*`/`X-GolfDigest-*`/`X-GolfPartner-*`/`X-FestivalGolf-*`/`X-GolfValue-*`/`X-Kasumigaseki-*`/`X-KawanaGC-*`/`X-NaruoGC-*`/`X-HironoGC-*`/`X-TokyoGC-*`/`X-AsamaGC-*`/`X-FujiGC-*`/`X-SenumaGC-*`/`X-OaraiGC-*`/`X-TopGolf-*`/`X-DrivingRange-*`/`X-IndoorGolf-*`/`X-SimGolf-*`/`X-GolfLesson-*`/`X-CountryClub-*`/`X-TeeTime-*` 等 は場機の通知記録 — 送信側が書くことは自称。会員権・予約確認・コンペ賞品の偽装はゴルファー狙い詐欺の典型手口。(スポーツ用品機は D529)
- **修正**: `Envelope` に `golfcourse_marks` + `has_golfcourse_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 場印の自署を問え。

### Security — D600: `X-Joshuya-*`/`X-Casting-*`/`X-DaiwaSeiko-*` 等の釣具・フィッシング印自称が未検査

- **問題**: `X-Joshuya-*` (上州屋)、`X-Casting-*` (キャスティング)、`X-DaiwaSeiko-*` (ダイワ精工)、`X-Tsurigu-*`/`X-FishingYu-*`/`X-Gamakatsu-*`/`X-Megabass-*`/`X-Jackall-*`/`X-Issei-*`/`X-Zappu-*`/`X-OSP-*`/`X-EvergreenFishing-*`/`X-Marukyu-*`/`X-Sasame-*`/`X-OwnerHook-*`/`X-Varivas-*`/`X-Sunline-*`/`X-TorayFishing-*`/`X-DuelFishing-*`/`X-YoZuri-*`/`X-MariaFishing-*`/`X-TackleBerry-*`/`X-BunBunTsurigu-*`/`X-PointTsurigu-*`/`X-Fisherman-*`/`X-FlyFishing-*`/`X-Tenkara-*`/`X-BoatFishing-*`/`X-FishingMaru-*`/`X-TsuriMaru-*` 等 は釣機の通知記録 — 送信側が書くことは自称。限定ルアー・釣り船予約・ポイント失効の偽装は釣り人狙い詐欺の典型手口。(シマノは D577、BassPro は既存族)
- **修正**: `Envelope` に `fishing_marks` + `has_fishing_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 釣印の自署を問え。

### Security — D601: `X-Hakuyosha-*`/`X-PonyCleaning-*`/`X-Sentakubin-*` 等のクリーニング・宅配洗濯印自称が未検査

- **問題**: `X-Hakuyosha-*` (白洋舎)、`X-PonyCleaning-*` (ポニークリーニング)、`X-Sentakubin-*` (せんたく便)、`X-HopeCleaning-*`/`X-CleanKing-*`/`X-Linavis-*`/`X-Kireina-*`/`X-DeaCleaning-*`/`X-FranceYa-*`/`X-PajamaCleaning-*`/`X-KuriRaba-*`/`X-Lenet-*`/`X-CleaningMonster-*`/`X-MyCleaning-*`/`X-KuriEpan-*`/`X-Tosho-*`/`X-Mammy-*`/`X-Kurie-*`/`X-Sansuisha-*`/`X-Whity-*`/`X-RebonCleaning-*`/`X-PontCleaning-*`/`X-CleaningDebut-*`/`X-KuruPlus-*`/`X-Swany-*`/`X-YuukiCleaning-*`/`X-Fuurin-*`/`X-KireiOukoku-*`/`X-CleanLife-*`/`X-HappyCleaning-*`/`X-SankoCleaning-*`/`X-CleaningExpress-*`/`X-SentakuYa-*`/`X-CleaningPro-*`/`X-DepotCleaning-*`/`X-Cleaning24-*`/`X-SumaClean-*`/`X-CleanNote-*`/`X-RoyalClean-*`/`X-LuxuryClean-*`/`X-BridalClean-*`/`X-SuitClean-*`/`X-FutonClean-*`/`X-KutsuClean-*`/`X-BagClean-*`/`X-FurClean-*`/`X-LeatherClean-*` 等 は濯機の通知記録 — 送信側が書くことは自称。預かり品完了・保管期限・送料請求の偽装はクリーニング詐欺の典型手口。
- **修正**: `Envelope` に `cleaning_marks` + `has_cleaning_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 濯印の自署を問え。

### Security — D596: `X-Isejingu-*`/`X-Meijijingu-*`/`X-IzumoTaisha-*` 等の神社仏閣・宗教印自称が未検査

- **問題**: `X-Isejingu-*` (伊勢神宮)、`X-Meijijingu-*` (明治神宮)、`X-IzumoTaisha-*` (出雲大社)、`X-FushimiInari-*`/`X-Sensoji-*`/`X-Kinkakuji-*`/`X-Kiyomizudera-*`/`X-Todaiji-*`/`X-Koyasan-*`/`X-Hieizan-*`/`X-Zenkoji-*`/`X-Naritasan-*`/`X-Dazaifu-*`/`X-SumiyoshiTaisha-*`/`X-AtsutaJingu-*`/`X-HikawaJinja-*`/`X-HiedaJinja-*`/`X-Tsurugaoka-*`/`X-KitanoTenmangu-*`/`X-Itsukushima-*`/`X-SuwaTaisha-*`/`X-KashimaJingu-*`/`X-KatoriJingu-*`/`X-Ishikiri-*`/`X-UsaJingu-*`/`X-YahikoJinja-*`/`X-Shirahige-*`/`X-KetaTaisha-*`/`X-KagoshimaJingu-*`/`X-MotoIse-*`/`X-Konpira-*`/`X-OyamaAfuri-*`/`X-Kunozan-*`/`X-Toshogu-*`/`X-Rinnoji-*`/`X-Chusonji-*`/`X-Motsuji-*`/`X-Zuiganji-*`/`X-Eiheiji-*`/`X-Sojiji-*`/`X-Chionin-*`/`X-HigashiHonganji-*`/`X-NishiHonganji-*`/`X-Tenryuji-*`/`X-Nanzenji-*`/`X-Daitokuji-*`/`X-Myoshinji-*`/`X-Kenninji-*`/`X-Tofukuji-*`/`X-Ryoanji-*`/`X-Ginkakuji-*`/`X-Saihoji-*`/`X-Horyuji-*`/`X-Yakushiji-*`/`X-Toshodaiji-*`/`X-Saidaiji-*`/`X-Shitennoji-*`/`X-Katsuoji-*`/`X-Nakayamadera-*`/`X-Zojoji-*`/`X-TsukijiHongwanji-*` 等 は社機の通知記録 — 送信側が書くことは自称。祈祷料・お布施・御朱印・法要案内の偽装は信仰悪用詐欺の典型手口。
- **修正**: `Envelope` に `shrine_marks` + `has_shrine_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 社印の自署を問え。

### Security — D597: `X-WeWork-*`/`X-Regus-*`/`X-Servcorp-*` 等のコワーキング・貸会議室印自称が未検査

- **問題**: `X-WeWork-*`/`X-Regus-*`/`X-Servcorp-*`/`X-CompassOffice-*`/`X-BusinessAirport-*`/`X-ExpertOffice-*`/`X-Resonance-*`/`X-TKP-*`/`X-DEFHub-*`/`X-Spaces-*`/`X-AntreSalon-*`/`X-IiOffice-*`/`X-H1T-*`/`X-WorkingSwitch-*`/`X-CoworkingSpot-*`/`X-RentalMeeting-*`/`X-RoomShare-*`/`X-OfficeShare-*`/`X-DropIn-*`/`X-ShareOffice-*`/`X-OfficePass-*`/`X-DeskPass-*`/`X-OfficeAnywhere-*`/`X-WorkationSpot-*`/`X-OfficeSuite-*`/`X-MeetingRoomPro-*`/`X-ConferenceRoomHub-*`/`X-WorkLounge-*`/`X-RemoteWorkHub-*`/`X-SatelliteOffice-*`/`X-OfficeRental-*`/`X-CoWorkHub-*`/`X-WorkFlex-*`/`X-OpenOfficeNet-*`/`X-SharedOffice-*`/`X-WorkBox-*`/`X-MeetingHub-*`/`X-RoomRental-*`/`X-OfficeBase-*`/`X-TeleworkHub-*`/`X-OfficeMetro-*`/`X-WorkPlaceNet-*`/`X-CoWorkSpace-*`/`X-OfficeLounge-*`/`X-BizAirport-*`/`X-OfficePort-*`/`X-WorkNest-*`/`X-OfficeHive-*`/`X-ShareDesk-*`/`X-HotDesk-*`/`X-BoothRental-*`/`X-PodiumOffice-*`/`X-OfficeLink-*`/`X-DeskNet-*`/`X-CoworkNet-*`/`X-OfficeGate-*`/`X-WorkGate-*`/`X-OfficeLoop-*` は働機の通知記録 — 送信側が書くことは自称。会議室予約・月額会費・入館証の偽装はリモートワーカー狙い詐欺の典型手口。
- **修正**: `Envelope` に `coworking_marks` + `has_coworking_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 働印の自署を問え。

### Security — D598: `X-Freee-*`/`X-MoneyForward-*`/`X-Yayoi-*` 等の会計ソフト・税務申告印自称が未検査

- **問題**: `X-Freee-*` (freee)、`X-MoneyForward-*` (マネーフォワード)、`X-Yayoi-*` (弥生会計)、`X-TKC-*`/`X-PCASoft-*`/`X-KanjoBugyo-*`/`X-JDL-*`/`X-KaikeiO-*`/`X-Tsukael-*`/`X-Misoca-*`/`X-Sweep-*`/`X-Zeirishi-*`/`X-Shinkoku-*`/`X-KakuteiShinkoku-*`/`X-DrakeTax-*`/`X-Lacerte-*`/`X-ProSeries-*`/`X-UltraTax-*`/`X-TaxSlayer-*`/`X-JacksonHewitt-*`/`X-LibertyTax-*`/`X-TaxReturn-*`/`X-RefundTax-*`/`X-KanpuTax-*`/`X-TaxHelper-*`/`X-MyTax-*`/`X-IncomeTax-*`/`X-CorpTax-*`/`X-Bookkeeping-*` 等 は税機の通知記録 — 送信側が書くことは自称。確定申告受理・還付金・税務通知の偽装は還付金詐欺の典型手口。(監査・格付機は D546、e-Tax・国税庁機は D518、TurboTax/H&R Block/TaxAct は既存族)
- **修正**: `Envelope` に `taxfiling_marks` + `has_taxfiling_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 税印の自署を問え。

### Security — D593: `X-Moppy-*`/`X-Hapitas-*`/`X-Gendama-*` 等のポイ活・お小遣いサイト印自称が未検査

- **問題**: `X-Moppy-*` (モッピー)、`X-Hapitas-*` (ハピタス)、`X-Gendama-*` (げん玉)、`X-PointIncome-*`/`X-Chobirich-*`/`X-PointTown-*`/`X-ECNavi-*`/`X-LifeMedia-*`/`X-PointAnytime-*`/`X-GetMoney-*`/`X-Warau-*`/`X-Sugotama-*`/`X-Powl-*`/`X-GPoint-*`/`X-PointLand-*`/`X-Macroidail-*`/`X-CoinOffer-*`/`X-OkaneMochi-*`/`X-PointFunnel-*`/`X-PointRibon-*`/`X-SumiPoint-*`/`X-PointWorld-*`/`X-PointBridge-*`/`X-PointFlow-*`/`X-Milama-*`/`X-Potora-*`/`X-MoneyTicket-*`/`X-PointOK-*`/`X-PointHunter-*`/`X-KozukaiPoint-*`/`X-PointStar-*`/`X-PointFan-*`/`X-PointGo-*`/`X-PointUp-*`/`X-PointDeals-*`/`X-Poita-*`/`X-RakutenPoint-*`/`X-KakuPoint-*`/`X-PointMessage-*`/`X-PointMail-*`/`X-PointMini-*`/`X-PointRace-*`/`X-ChibiPoint-*`/`X-PointGuide-*`/`X-Poicha-*`/`X-PointCatalog-*`/`X-PointStore-*`/`X-PotoraPoint-*`/`X-HapitasMini-*`/`X-PointTownship-*`/`X-PointSale-*`/`X-PointParadise-*`/`X-Gendamita-*`/`X-EbiPoint-*`/`X-NekoPoint-*` は稼機の通知記録 — 送信側が書くことは自称。ポイント増量・換金完了・獲得通知の偽装はポイ活詐欺の典型手口。(ポイント・決済機は D568)
- **修正**: `Envelope` に `pointkatsu_marks` + `has_pointkatsu_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 稼印の自署を問え。

### Security — D594: `X-Rirakuru-*`/`X-Raffine-*`/`X-Temomin-*` 等のマッサージ・整体・リラク印自称が未検査

- **問題**: `X-Rirakuru-*` (りらくる)、`X-Raffine-*` (ラフィネ)、`X-Temomin-*` (てもみん)、`X-KaradaFactory-*`/`X-Manistare-*`/`X-Rafure-*`/`X-Asubi-*`/`X-Mukatamu-*`/`X-Toraibu-*`/`X-Ribafi-*`/`X-Bantomiere-*`/`X-Taraso-*`/`X-MassagePlaza-*`/`X-FootJoy-*`/`X-Ashiraku-*`/`X-Temonigiri-*`/`X-TemomiLabo-*`/`X-BodyTune-*`/`X-Momivale-*`/`X-ChiroSuiden-*`/`X-MominoTsuchi-*`/`X-Tenowa-*`/`X-Hogushite-*`/`X-KaradaPlus-*`/`X-Rirakuya-*`/`X-Momitei-*`/`X-MomiYa-*`/`X-Genkido-*`/`X-Tsuyoshi-*`/`X-Nidanashi-*`/`X-MasajiKun-*`/`X-Hogusubi-*`/`X-Riraku-*`/`X-YutoriKan-*`/`X-Otenami-*`/`X-Ubub-*`/`X-Chiryoen-*`/`X-BodyLab-*`/`X-FootSalon-*`/`X-RefleKaikan-*`/`X-ItokiKaikan-*`/`X-MomiSukki-*`/`X-Rakua-*`/`X-Fumino-*`/`X-AshiMomi-*`/`X-NagomiTei-*`/`X-ShiatsuKan-*`/`X-AcuRetreat-*`/`X-SpaRise-*`/`X-MeroPeach-*`/`X-Nemomi-*`/`X-Hoguretu-*`/`X-TeShin-*`/`X-Hogureba-*`/`X-MomiLabo-*`/`X-RilakSPA-*`/`X-SoreEgao-*`/`X-KaradaRaku-*`/`X-FuwaRaku-*` は揉機の通知記録 — 送信側が書くことは自称。回数券・施術予約・コース勧誘の偽装はリラク詐欺の典型手口。
- **修正**: `Envelope` に `massage_marks` + `has_massage_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 揉印の自署を問え。

### Security — D595: `X-TimesPark-*`/`X-Times24-*`/`X-MitsuRepark-*` 等の駐車場・コインパーキング印自称が未検査

- **問題**: `X-TimesPark-*` (タイムズパーキング)、`X-Times24-*` (タイムズ)、`X-MitsuRepark-*` (三井のリパーク)、`X-NPC24H-*`/`X-ApplePark-*`/`X-TimesCar-*`/`X-NPCParking-*`/`X-Parca-*`/`X-WisdomCar-*`/`X-ELeaf-*`/`X-Seiyaken-*`/`X-NipponParking-*`/`X-ParkJPN-*`/`X-MiyamaPark-*`/`X-ParkMoto-*`/`X-MotoPark-*`/`X-ParkingLot-*`/`X-CoinPark-*`/`X-YorozuPark-*`/`X-SFC-Park-*`/`X-AoiPark-*`/`X-FudoPark-*`/`X-MotomachiPark-*`/`X-TokyoPark-*`/`X-NambaPark-*`/`X-KobePark-*`/`X-OsakaPark-*`/`X-NagoyaPark-*`/`X-SapporoPark-*`/`X-FukuokaPark-*`/`X-KanazawaPark-*`/`X-SendaiPark-*`/`X-HiroshimaPark-*`/`X-KitaPark-*`/`X-MinamiPark-*`/`X-RoutePark-*`/`X-MultiPark-*`/`X-StationPark-*`/`X-AirportPark-*`/`X-CenterPark-*`/`X-ParkYourCar-*`/`X-CarPark-*`/`X-OffStreet-*`/`X-InnerPark-*`/`X-ZonePark-*`/`X-RakudaPark-*`/`X-MotoChin-*`/`X-ValleyPark-*`/`X-MotoGate-*`/`X-ParkMate-*`/`X-MotoZone-*`/`X-ParkingNet-*`/`X-ParkingLab-*`/`X-ParkOnline-*`/`X-DigitalPark-*`/`X-SmartPark-*`/`X-MyParking-*` は停機の通知記録 — 送信側が書くことは自称。駐車違反金・月極料金・駐車場検索の偽装はドライバー狙い詐欺の典型手口。(自動車機は D521、車買取機は D572)
- **修正**: `Envelope` に `parking_marks` + `has_parking_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 停印の自署を問え。

### Security — D590: `X-Raksul-*`/`X-Printpac-*`/`X-Vistaprint-*` 等の印刷・名刺通販印自称が未検査

- **問題**: `X-Raksul-*` (ラクスル)、`X-Printpac-*` (プリントパック)、`X-Vistaprint-*` (Vistaprint)、`X-Graphic-*`/`X-Banfu-*`/`X-Irodori-*`/`X-Meishi21-*`/`X-Papuri-*`/`X-KingPrinters-*`/`X-Cocomite-*`/`X-PrintMall-*`/`X-NetPrintJP-*`/`X-PrintMarche-*`/`X-SpeedPrint-*`/`X-Kitamura-*`/`X-Jijinsha-*`/`X-Irori-*`/`X-PrintBuddy-*`/`X-Ashida-*`/`X-Primedia-*`/`X-Optimum-*`/`X-Pazza-*`/`X-Prijitsu-*`/`X-WePrint-*`/`X-OnPrint-*`/`X-BoxPrint-*`/`X-KinkoPrint-*`/`X-PrintMonster-*`/`X-Pixable-*`/`X-Moo-*`/`X-Shutterfly-*`/`X-CanvaPrint-*`/`X-Printful-*`/`X-GotPrint-*`/`X-OvernightPrints-*`/`X-UPrinting-*`/`X-PrintPlace-*`/`X-Jukebox-*`/`X-48HourPrint-*`/`X-Printify-*`/`X-Gelato-*`/`X-PrintReleaf-*`/`X-FedexOffice-*`/`X-StaplesPrint-*`/`X-OfficeDepotPrint-*`/`X-Smartpress-*`/`X-PrintRunner-*`/`X-UPrint-*`/`X-Printingforless-*`/`X-Imbue-*`/`X-Zazzle-*`/`X-CafePress-*`/`X-Redbubble-*`/`X-Society6-*`/`X-Teepublic-*`/`X-Threadless-*`/`X-Spreadshop-*`/`X-PrintBest-*` は刷機の通知記録 — 送信側が書くことは自称。名刺発注・チラシ印刷・データ入稿の偽装は小規模事業者狙い詐欺の典型。
- **修正**: `Envelope` に `printing_marks` + `has_printing_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 刷印の自署を問え。

### Security — D591: `X-Tsukui-*`/`X-Care21-*`/`X-Solasto-*` 等の介護・ケアサービス印自称が未検査

- **問題**: `X-Tsukui-*` (ツクイ)、`X-Care21-*` (ケア21)、`X-Solasto-*` (ソラスト)、`X-SentCare-*`/`X-Kiracare-*`/`X-MagokoroKaigo-*`/`X-CarePartner-*`/`X-ActCare-*`/`X-MiraiCare-*`/`X-GoodCare-*`/`X-SigmaShio-*`/`X-Hohoemi-*`/`X-JobMedleyKaigo-*`/`X-UrbanCare-*`/`X-Longterm-*`/`X-Nimpo-*`/`X-SeniorLife-*`/`X-Ekr-*`/`X-TsukuiStaff-*`/`X-TsukuiHouse-*`/`X-CareNeeds-*`/`X-Fukushi-*`/`X-FukushiWorker-*`/`X-Carema-*`/`X-NursingCare-*`/`X-KaigoGym-*`/`X-NursingHome-*`/`X-DayService-*`/`X-HomeKaigo-*`/`X-KaigoBaito-*`/`X-KaigoPartner-*`/`X-VisitingCare-*`/`X-Asuki-*`/`X-HomeService-*`/`X-KaigoShien-*`/`X-Yuai-*`/`X-OliveCare-*`/`X-Cocofump-*`/`X-FukushiSogo-*`/`X-Ikikai-*`/`X-Medicus-*`/`X-MedicalCare-*`/`X-DoHaKaigo-*`/`X-SupportLife-*`/`X-Sawayaka-*`/`X-Mimy-*`/`X-KaigoPhone-*`/`X-Withma-*`/`X-CareStyle-*`/`X-HumanCare-*`/`X-MotherCare-*`/`X-Tsubomi-*`/`X-OrangeCare-*`/`X-HidamariCare-*`/`X-ShinwaKaigo-*`/`X-SmileKaigo-*`/`X-KokoroKaigo-*`/`X-RivaKaigo-*`/`X-HarmonyCare-*`/`X-MaruKaigo-*` は介機の通知記録 — 送信側が書くことは自称。介護費用・補助金・サービス変更の偽装は高齢者・家族狙い詐欺の典型。(オンライン診療機は D575)
- **修正**: `Envelope` に `eldercare_marks` + `has_eldercare_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 介印の自署を問え。

### Security — D592: `X-HokenNoMadoguchi-*`/`X-HokenMinoshi-*`/`X-ManeDoc-*` 等の保険相談・比較印自称が未検査

- **問題**: `X-HokenNoMadoguchi-*` (ほけんの窓口)、`X-HokenMinoshi-*` (保険見直し本舗)、`X-ManeDoc-*` (マネードクター)、`X-HokenClinic-*`/`X-HokenSoudan-*`/`X-HokenSenka-*`/`X-HokenIchiba-*`/`X-HokenTerrace-*`/`X-HokenHouse-*`/`X-HokenMammoth-*`/`X-MitsubachiHoken-*`/`X-Boutatsu-*`/`X-HokenBuffet-*`/`X-HokenHyakka-*`/`X-HokenConnect-*`/`X-LifullHoken-*`/`X-NiaeruHoken-*`/`X-IryoHoken-*`/`X-GanHoken-*`/`X-NinshinHoken-*`/`X-KodomoHoken-*`/`X-PetHoken-*`/`X-GakueiHoken-*`/`X-RetirementHoken-*`/`X-MitumoriHoken-*`/`X-CompareHoken-*`/`X-HokenReview-*`/`X-HokenAdvice-*`/`X-HokenDesign-*`/`X-HokenSelect-*`/`X-HokenFair-*`/`X-HokenGate-*`/`X-HokenConsult-*`/`X-HokenLabo-*`/`X-HokenMimimoto-*`/`X-HokenNavi-*`/`X-MyHoken-*`/`X-HokenGarden-*`/`X-HokenSquare-*`/`X-HokenStage-*`/`X-HokenSken-*`/`X-HokenLine-*`/`X-HokenPro-*`/`X-HokenNet-*`/`X-HokenFirst-*`/`X-HokenPocket-*`/`X-HokenPlanet-*`/`X-HokenSpace-*`/`X-HokenDai-*`/`X-HokenDono-*`/`X-HokenHiroba-*`/`X-HokenJuku-*`/`X-HokenMint-*`/`X-HokenPia-*`/`X-HokenSalon-*`/`X-HokenStyle-*`/`X-HokenTable-*`/`X-HokenVoice-*`/`X-HokenWindow-*`/`X-HokenWorld-*` は保機の通知記録 — 送信側が書くことは自称。見直し相談・契約更改・給付金請求の偽装は保険勧誘詐欺の典型。(保険会社機は D519)
- **修正**: `Envelope` に `insconsult_marks` + `has_insconsult_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 保印の自署を問え。

### Security — D587: `X-Yazuya-*`/`X-Egao-*`/`X-NatureMade-*` 等のサプリメント・健康食品印自称が未検査

- **問題**: `X-Yazuya-*` (やずや)、`X-Egao-*` (えがお)、`X-NatureMade-*` (ネイチャーメイド)、`X-Kyusai-*`/`X-YamamotoKanpo-*`/`X-LifeSupplement-*`/`X-USANA-*`/`X-Orihiro-*`/`X-ItohKanpo-*`/`X-SuntoryWellness-*`/`X-AsahiFoods-*`/`X-Ogaland-*`/`X-FineJapan-*`/`X-MoriSupplement-*`/`X-Hifumi-*`/`X-Nunokame-*`/`X-Ebis-*`/`X-BelleSere-*`/`X-SeedComs-*`/`X-Fukumi-*`/`X-Grassju-*`/`X-AFC-*`/`X-NatureLife-*`/`X-HealthHelper-*`/`X-SupplementJP-*`/`X-KaigoSapri-*`/`X-VitaSapri-*`/`X-PuritansPride-*`/`X-NowFoods-*`/`X-Solgar-*`/`X-Thorne-*`/`X-LifeExtension-*`/`X-DoctorBest-*`/`X-Jarrow-*`/`X-Swanson-*`/`X-NaturesWay-*`/`X-GardenOfLife-*`/`X-MegaFood-*`/`X-RainbowLight-*`/`X-SourceNaturals-*`/`X-Nutrigold-*`/`X-Sundown-*`/`X-NatureBounty-*`/`X-Natrol-*`/`X-Caltrate-*`/`X-Centrum-*`/`X-OneADay-*`/`X-Estheliv-*`/`X-Heliom-*`/`X-Mynus-*`/`X-Yawata-*`/`X-Revon-*`/`X-HyaDuo-*`/`X-MenardSupp-*`/`X-PolaSupp-*`/`X-ShiseidoSupp-*`/`X-OrbisSupp-*` は滋機の通知記録 — 送信側が書くことは自称。初回無料・定期購入・効能謳いの偽装は健康食品詐欺の典型。(化粧品機は D531、製薬機は D542)
- **修正**: `Envelope` に `supplement_marks` + `has_supplement_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 滋印の自署を問え。

### Security — D588: `X-Crecla-*`/`X-AquaClara-*`/`X-Frecious-*` 等のウォーターサーバー・宅配水印自称が未検査

- **問題**: `X-Crecla-*` (クリクラ)、`X-AquaClara-*` (アクアクララ)、`X-Frecious-*` (フレシャス)、`X-CosmoWater-*`/`X-PremiumWater-*`/`X-Urunon-*`/`X-Alpina-*`/`X-Kirala-*`/`X-OneWay-*`/`X-Nafiel-*`/`X-FujiNoYusui-*`/`X-ShinanoYusui-*`/`X-EcoWater-*`/`X-WaterBox-*`/`X-AmadanaWater-*`/`X-Locc-*`/`X-KiralaWater-*`/`X-MizuNoKagayaki-*`/`X-AlpesWater-*`/`X-FujiWater-*`/`X-Rakusui-*`/`X-FujiKyokusui-*`/`X-ShingenWater-*`/`X-WaterServer-*`/`X-KanadenWater-*`/`X-AquaWave-*`/`X-MizunoHikari-*`/`X-FamiPure-*`/`X-MizuLand-*`/`X-PureBlu-*`/`X-Kyoubun-*`/`X-AquaStyle-*`/`X-TokiWater-*`/`X-AquaCube-*`/`X-NomuWater-*`/`X-DydoWater-*`/`X-YamatoWater-*`/`X-DewLand-*`/`X-OyuMizu-*`/`X-SierraWater-*`/`X-MaruMizu-*`/`X-QuolofWater-*`/`X-AquaPartner-*`/`X-WaterStand-*`/`X-KiranoWater-*`/`X-HatoMizu-*`/`X-NipponMizu-*`/`X-MizuKawa-*`/`X-YuukiWater-*`/`X-Suigen-*`/`X-SpringMizu-*`/`X-FujiPure-*`/`X-ItoEnWater-*`/`X-Shizuku-*`/`X-OzekiWater-*`/`X-AsahiWater-*`/`X-MizuHi-*` は水機の通知記録 — 送信側が書くことは自称。サーバー無料・定期水代・保守点検の偽装は水商売詐欺の典型。
- **修正**: `Envelope` に `waterserver_marks` + `has_waterserver_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 水印の自署を問え。

### Security — D589: `X-NihonMA-*`/`X-StrikeMA-*`/`X-Batonz-*`/`X-Tranbi-*` 等の M&A・事業承継印自称が未検査

- **問題**: `X-NihonMA-*` (日本M&Aセンター)、`X-StrikeMA-*` (ストライク)、`X-Batonz-*` (バトンズ)、`X-Tranbi-*` (トランビ)、`X-MACP-*`/`X-Atracs-*`/`X-MASoken-*`/`X-Ondec-*`/`X-ESNetworks-*`/`X-Inte-*`/`X-Fundbook-*`/`X-MATech-*`/`X-Succession-*`/`X-Shokibo-*`/`X-MAOnline-*`/`X-JMACenter-*`/`X-MAAdvisors-*`/`X-NihonJiba-*`/`X-ChushoMA-*`/`X-BizReachSuccession-*`/`X-MATrust-*`/`X-RecofMA-*`/`X-YukoMA-*`/`X-Manebi-*`/`X-JVCM-*`/`X-MatchPoint-*`/`X-TsugiTe-*`/`X-Keieisoken-*`/`X-ShoninMA-*`/`X-MAParners-*`/`X-Inforights-*`/`X-UsamiMA-*`/`X-StrategicM-*`/`X-KeitakuMA-*`/`X-MABridge-*`/`X-MiraiMA-*`/`X-ErnstMA-*`/`X-MAConsulting-*`/`X-CorrMA-*`/`X-AozoraMA-*`/`X-RiverMA-*`/`X-CraftMA-*`/`X-FukuiMA-*`/`X-TokyoMA-*`/`X-NipponBridge-*`/`X-AccelMA-*`/`X-BridgePartner-*`/`X-Kachidoki-*`/`X-SouzokuMA-*`/`X-KeisanMA-*`/`X-JitsumuMA-*`/`X-SogoMA-*`/`X-ShinsuiMA-*` は継機の通知記録 — 送信側が書くことは自称。買収案件・承継相談・仲介手数料の偽装は中小企業狙い BEC の典型。(監査・コンサル機は D546)
- **修正**: `Envelope` に `maadvisory_marks` + `has_maadvisory_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 継印の自署を問え。

### Security — D584: `X-Bears-*`/`X-CaSy-*`/`X-Osoujihonpo-*` 等の家事代行・ハウスクリーニング印自称が未検査

- **問題**: `X-Bears-*` (ベアーズ)、`X-CaSy-*` (CaSy)、`X-Osoujihonpo-*` (おそうじ本舗)、`X-Minimaid-*`/`X-Pinai-*`/`X-Taskaji-*`/`X-Kajita-*`/`X-Kajitaku-*`/`X-Mitsume-*`/`X-MaggieMaid-*`/`X-Iekeeping-*`/`X-Okatazuke-*`/`X-Edai-*`/`X-Housekeeping-*`/`X-Umamori-*`/`X-Cathand-*`/`X-TokyoOsoji-*`/`X-Maruzyou-*`/`X-Arukaji-*`/`X-Rakumama-*`/`X-Kajiapo-*`/`X-Osoji-*`/`X-MerryMaid-*`/`X-DuskinMaid-*`/`X-MollyMaid-*`/`X-Homejoy-*`/`X-Handy-*`/`X-Takl-*`/`X-Maids-*`/`X-Tidy-*`/`X-Takuji-*`/`X-Hitosaji-*`/`X-Hatarako-*`/`X-Grapes-*`/`X-Bikubo-*`/`X-Sansei-*`/`X-Daikou-*`/`X-PickMe-*`/`X-HouseCall-*`/`X-Zehitomo-*`/`X-Kurashino-*`/`X-Mitibata-*`/`X-Odegawa-*`/`X-Osamade-*`/`X-HouseKeeper-*`/`X-Sumai-*`/`X-Cocole-*`/`X-Asumi-*`/`X-Rakuchin-*`/`X-Suki-*`/`X-Aizin-*`/`X-Osekkai-*` は房機の通知記録 — 送信側が書くことは自称。見積提示・定期契約・クリーニング代金の偽装は高齢者狙い詐欺の典型。(警備・施設機は D548)
- **修正**: `Envelope` に `housekeeping_marks` + `has_housekeeping_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 房印の自署を問え。

### Security — D585: `X-QVC-*`/`X-Japanet-*`/`X-Nissen-*` 等の通販・TVショッピング印自称が未検査

- **問題**: `X-QVC-*` (QVC)、`X-Japanet-*` (ジャパネット)、`X-Nissen-*` (ニッセン)、`X-ShopChannel-*`/`X-Bellemaison-*`/`X-Cecile-*`/`X-Dinos-*`/`X-Scroll-*`/`X-CatalogHouse-*`/`X-ShopJapan-*`/`X-OakLawn-*`/`X-Image-*`/`X-PeachJohn-*`/`X-Belluna-*`/`X-Felissimo-*`/`X-Halmek-*`/`X-Senchikai-*`/`X-NihonOnegai-*`/`X-ShoppingChannel-*`/`X-TVShop-*`/`X-HSN-*`/`X-Evine-*`/`X-IdealWorld-*`/`X-Highland-*`/`X-TJC-*`/`X-Qoo10Shop-*`/`X-HomeShopping-*`/`X-RakutenIchibaShop-*`/`X-PlusShop-*`/`X-Ikkyu-*`/`X-SelectShop-*`/`X-Tsuhanshop-*`/`X-KatazukeClub-*`/`X-Nippan-*`/`X-Rakuno-*`/`X-Yumiku-*`/`X-Vantan-*`/`X-Stylecover-*`/`X-DHCShop-*`/`X-OtonaMuse-*`/`X-Rusia-*`/`X-Mikko-*`/`X-RyuRyu-*`/`X-Urara-*`/`X-Nolty-*`/`X-UrbanShop-*`/`X-Kumonoit-*`/`X-Sunao-*`/`X-Modus-*`/`X-Shimauma-*`/`X-PixelShop-*` は購機の通知記録 — 送信側が書くことは自称。定期購入・商品未着・解約違約金の偽装は通販詐欺の典型。(楽天/メルカリ等 EC 機は既存族、宅食機は D555)
- **修正**: `Envelope` に `mailorder_marks` + `has_mailorder_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 購印の自署を問え。

### Security — D586: `X-AichiLaw-*`/`X-TokyoMinerva-*`/`X-Avance-*` 等の債務整理・過払い金印自称が未検査

- **問題**: `X-AichiLaw-*` (愛知司法書士)、`X-TokyoMinerva-*` (東京ミネルヴァ)、`X-Avance-*` (アヴァンス)、`X-NihonPlum-*`/`X-DaiichiSogo-*`/`X-HomeWon-*`/`X-WithYou-*`/`X-Hibari-*`/`X-Sugiyama-*`/`X-GreenLeaf-*`/`X-Masuda-*`/`X-Licio-*`/`X-Kabarai-*`/`X-Saimuseiri-*`/`X-Hitotohito-*`/`X-FrontierLaw-*`/`X-KokoroNoMori-*`/`X-Shihoushoshi-*`/`X-JMAssociates-*`/`X-LegalPro-*`/`X-NihonSaimu-*`/`X-TokiwaLaw-*`/`X-ShinyoLaw-*`/`X-SaiseiLaw-*`/`X-HikariLaw-*`/`X-MatsuriLaw-*`/`X-ChuoLaw-*`/`X-FrontierAdvisors-*`/`X-Kanbe-*`/`X-OgawaLaw-*`/`X-TamaruyaLaw-*`/`X-AikoLaw-*`/`X-Reisui-*`/`X-Tomorrow-*`/`X-SunriseLaw-*`/`X-MiraiLaw-*`/`X-HopeLaw-*`/`X-RenaissanceLaw-*`/`X-HarvestLaw-*`/`X-ArchLaw-*`/`X-BaseLaw-*`/`X-HikoLaw-*`/`X-TokyoLaw-*`/`X-OsakaLaw-*`/`X-NagoyaLaw-*`/`X-Kabaraikin-*`/`X-KanyuLaw-*`/`X-SaimuShori-*`/`X-MinnaSaimu-*`/`X-ToshoLaw-*`/`X-UraraLaw-*`/`X-NihonLaw-*`/`X-GrandLaw-*`/`X-FujiLaw-*`/`X-YamatoLaw-*` は務機の通知記録 — 送信側が書くことは自称。過払い金報酬・債務整理手数料の偽装は債務者狙い詐欺の典型。(法務サービス機は D523、消費者金融機は D581)
- **修正**: `Envelope` に `debtrelief_marks` + `has_debtrelief_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 務印の自署を問え。

### Security — D581: `X-Acom-*`/`X-Promise-*`/`X-Aiful-*`/`X-Mobit-*` 等の消費者金融・カードローン印自称が未検査

- **問題**: `X-Acom-*` (アコム)、`X-Promise-*` (プロミス)、`X-Aiful-*` (アイフル)、`X-Mobit-*` (モビット)、`X-LakeALSA-*`/`X-Central-*`/`X-Futaba-*`/`X-DirectOne-*`/`X-Fukuho-*`/`X-Eiwa-*`/`X-SkyOffice-*`/`X-Canet-*`/`X-Arco-*`/`X-Arrow-*`/`X-Lifet-*`/`X-Mirai-*`/`X-Ufa-*`/`X-HelloHappy-*`/`X-Espoir-*`/`X-Aline-*`/`X-APlus-*`/`X-SMBCMobby-*`/`X-AuJibun-*`/`X-Hanacred-*`/`X-Askpa-*`/`X-Fukumaru-*`/`X-Nyusen-*`/`X-Sekishin-*`/`X-Taisei-*`/`X-Haruka-*`/`X-LifeSuite-*`/`X-Columbia-*`/`X-Anfan-*`/`X-Fujimaru-*`/`X-Kimura-*`/`X-AIUCred-*`/`X-SHinki-*`/`X-SmileShosan-*`/`X-Harukaze-*`/`X-BellunaMoney-*`/`X-SpaceRental-*` は銭機の通知記録 — 送信側が書くことは自称。残高確認・支払催促・審査通過の偽装は闇金・架空請求の典型。(`X-VISA-*`/`X-Amex-*`/`X-Saison-*`/`X-オリコ-*` 等のカード機は D567、銀行機は D514/D554)
- **修正**: `Envelope` に `consumerloan_marks` + `has_consumerloan_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 銭印の自署を問え。

### Security — D582: `X-Akachan-*`/`X-Nishimatsuya-*`/`X-Mikihouse-*` 等のベビー・子育て印自称が未検査

- **問題**: `X-Akachan-*` (アカチャンホンポ)、`X-Nishimatsuya-*` (西松屋)、`X-Mikihouse-*` (ミキハウス)、`X-Birthday-*`/`X-Pigeon-*`/`X-Combi-*`/`X-Aprica-*`/`X-BabiesRUs-*`/`X-Familiar-*`/`X-ToysRUs-*`/`X-Bornelund-*`/`X-Dadway-*`/`X-Ergobaby-*`/`X-Babybjorn-*`/`X-Medela-*`/`X-Drbetta-*`/`X-Beanstalk-*`/`X-Wakodo-*`/`X-MeijiBaby-*`/`X-MorinagaBaby-*`/`X-Akasugu-*`/`X-Tamahiyo-*`/`X-ZexyBaby-*`/`X-Babycome-*`/`X-Ninaas-*`/`X-PuremaBaby-*`/`X-BellemaBaby-*`/`X-Farbe-*`/`X-ChouChou-*`/`X-BabyFan-*`/`X-Kodomono-*`/`X-Mamanoco-*`/`X-Futafuta-*`/`X-Kiddyland-*`/`X-Bumbo-*`/`X-SkipHop-*`/`X-Cybex-*`/`X-Britax-*`/`X-MaxiCosi-*`/`X-Graco-*`/`X-Chicco-*`/`X-Evenflo-*`/`X-4moms-*`/`X-BabyDan-*`/`X-Babyzen-*`/`X-Stokke-*`/`X-Leander-*`/`X-Kidco-*`/`X-RecaroKids-*`/`X-LoveToDream-*`/`X-Aptamil-*`/`X-Similac-*` は児機の通知記録 — 送信側が書くことは自称。出産祝い・育児グッズ・粉ミルク割引の偽装は新米親狙い詐欺の典型。
- **修正**: `Envelope` に `baby_marks` + `has_baby_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 児印の自署を問え。

### Security — D583: `X-Hibiya-*`/`X-Hanacupid-*`/`X-Teleflora-*`/`X-Interflora-*` 等の花・フラワーギフト印自称が未検査

- **問題**: `X-Hibiya-*` (日比谷花壇)、`X-Hanacupid-*` (花キューピット)、`X-AoyamaFlower-*` (青山フラワーマーケット)、`X-Hitohana-*`/`X-Sakaseru-*`/`X-HanaRe-*`/`X-BalloonShop-*`/`X-Hanagift-*`/`X-Fleuret-*`/`X-PremiumGarden-*`/`X-FirstFlower-*`/`X-AmanFlower-*`/`X-HibiyaKadan-*`/`X-1-800Flowers-*`/`X-ProFlowers-*`/`X-FTD-*`/`X-Teleflora-*`/`X-Interflora-*`/`X-BloomAndWild-*`/`X-FreddiesFlowers-*`/`X-TheBouqs-*`/`X-UrbanStems-*`/`X-Bloomon-*`/`X-EFlorist-*`/`X-SerenataFlowers-*`/`X-FlowerBud-*`/`X-Farmgirl-*`/`X-SendFlowers-*`/`X-FromYouFlowers-*`/`X-EnjoyFlowers-*`/`X-BloomsyBox-*`/`X-FieldBouquet-*`/`X-BotanyBox-*`/`X-FlyingFlowers-*`/`X-FlowerCard-*`/`X-PosyBouquet-*`/`X-PetalBox-*`/`X-LifullFlower-*`/`X-Hanamaru-*`/`X-Hanayoshi-*`/`X-FloristJapan-*`/`X-MotherDay-*`/`X-HanaOukoku-*`/`X-MerciBlossom-*`/`X-Orchidee-*`/`X-DahliaFlower-*`/`X-BlueJack-*`/`X-Mokuren-*`/`X-SakuraBloomy-*`/`X-HanaNoMura-*`/`X-Ohanashi-*`/`X-PetitHana-*`/`X-FlowerIs-*`/`X-HanaPrime-*`/`X-Floriado-*`/`X-FineFlowers-*`/`X-ArtistFlower-*`/`X-FlowerLand-*`/`X-FlowerKingdom-*`/`X-Hanasika-*`/`X-Kajuen-*` は花機の通知記録 — 送信側が書くことは自称。母の日・開店祝い・お供え花の偽装はギフト詐欺の典型。
- **修正**: `Envelope` に `flower_marks` + `has_flower_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 花印の自署を問え。

### Security — D578 `X-Takarakuji-*`/`X-Loto6-*`/`X-Powerball-*` 等の宝くじ・ロト・懸賞当選印自称が未検査

- **問題**: `X-Takarakuji-*` (宝くじ)、`X-Loto6-*` (ロト 6)、`X-Powerball-*` (Powerball)、`X-Loto7-*`/`X-MiniLoto-*`/`X-Numbers-*`/`X-Bingo5-*`/`X-TakarakujiScratch-*`/`X-MegaMillions-*`/`X-EuroMillions-*`/`X-Lotto6Aus49-*`/`X-OzLotto-*`/`X-LottoMax-*`/`X-SuperEnalotto-*`/`X-ElGordo-*`/`X-DreamJumbo-*`/`X-NenmatsuJumbo-*`/`X-SummerJumbo-*`/`X-HalloweenJumbo-*`/`X-ValentineJumbo-*`/`X-GreenJumbo-*`/`X-Big-*`/`X-MiniBig-*`/`X-TotoGoal-*`/`X-Winner-*`/`X-Lottery-*`/`X-Kuji-*`/`X-KujiHonpo-*`/`X-RakutenToto-*`/`X-ClubToto-*`/`X-TotoVote-*`/`X-MiniToto-*`/`X-Goal3-*`/`X-Sportec-*`/`X-LotteryOffice-*`/`X-StateLottery-*`/`X-Camelot-*`/`X-Loterias-*`/`X-Sorteos-*`/`X-MyLotto-*`/`X-Intralot-*` は宝機の通知記録 — 送信側が書くことは自称。高額当選・手数料前払いの偽装は宝くじ詐欺の典型。(`X-Bet365-*`/`X-VeraJohn-*`/`X-toto-*` 等の賭博機は D547 で検出済み)
- **修正**: `Envelope` に `lottery_marks` + `has_lottery_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 宝印の自署を問え。

### Security — D579: `X-DaiwaHouse-*`/`X-Lixil-*`/`X-HomePro-*` 等の住宅メーカー・リフォーム印自称が未検査

- **問題**: `X-DaiwaHouse-*` (大和ハウス)、`X-Lixil-*` (LIXIL)、`X-HomePro-*` (ホームプロ)、`X-Sekisui-*`/`X-SekisuiHouse-*`/`X-SumitomoRingyo-*`/`X-Misawa-*`/`X-Hebel-*`/`X-Ichijo-*`/`X-SekisuiHeim-*`/`X-Tamahome-*`/`X-AifulHome-*`/`X-Cleverly-*`/`X-ToyotaHome-*`/`X-YKKAP-*`/`X-SankyoAlumi-*`/`X-NikkaHome-*`/`X-RishoNavi-*`/`X-PanasonicHomes-*`/`X-MitsuiHome-*`/`X-SwedenHouse-*`/`X-HomeAgent-*`/`X-MisawaHome-*`/`X-Toso-*`/`X-Cleanup-*`/`X-TakaraStandard-*`/`X-WoodOne-*`/`X-Daiken-*`/`X-MaezawaKasei-*`/`X-KyoceraHomes-*`/`X-AqaHome-*`/`X-Aqura-*`/`X-HikariHome-*`/`X-Arukotto-*`/`X-ALTS-*`/`X-AokiHome-*`/`X-Bess-*`/`X-MujiHome-*`/`X-Freesia-*`/`X-Aibro-*`/`X-HigashiConstruction-*`/`X-WatanabeKobo-*`/`X-Shinkenchiku-*`/`X-SxL-*`/`X-Yamatoya-*` は宅機の通知記録 — 送信側が書くことは自称。無料点検・リフォーム見積・耐震診断の偽装は点検商法・リフォーム詐欺の典型。
- **修正**: `Envelope` に `housing_marks` + `has_housing_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 宅印の自署を問え。

### Security — D580: `X-IiSougi-*`/`X-KamakuraShinsho-*`/`X-Tear-*` 等の葬儀・終活印自称が未検査

- **問題**: `X-IiSougi-*` (いい葬儀)、`X-KamakuraShinsho-*` (鎌倉新書)、`X-Tear-*` (ティア)、`X-SagamiSourei-*`/`X-Ceremore-*`/`X-Koeisha-*`/`X-AeonSousai-*`/`X-Kokoro-*`/`X-Hanasou-*`/`X-YasashiiOsoushiki-*`/`X-Terakura-*`/`X-EndingPark-*`/`X-HinataOsoushiki-*`/`X-Souzoku-*`/`X-MemorialArt-*`/`X-OsoushikiReview-*`/`X-Eirii-*`/`X-LifeEnder-*`/`X-Rakushu-*`/`X-Owakare-*`/`X-Ens-*`/`X-Sousaiya-*`/`X-Tensou-*`/`X-Matsuya-*`/`X-Heian-*`/`X-Koushaisha-*`/`X-HeianPalace-*`/`X-WorldRe-*`/`X-Dainippon-*`/`X-Tokiwa-*`/`X-TokiwaSougi-*`/`X-EcoSougi-*`/`X-YoshinoSoushiki-*`/`X-Hisago-*`/`X-Boko-*`/`X-FamilyCera-*`/`X-MainHall-*`/`X-Mitou-*`/`X-Comet-*`/`X-Stella-*`/`X-Sora-*`/`X-Oyasumi-*`/`X-Chocho-*`/`X-KazokuSo-*`/`X-Nouveau-*`/`X-Graceful-*`/`X-Royal-*`/`X-Farewell-*` は葬機の通知記録 — 送信側が書くことは自称。葬儀費用前払い・墓石仏壇高額勧誘・香典返しの偽装は葬儀詐欺の典型。
- **修正**: `Envelope` に `funeral_marks` + `has_funeral_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 葬印の自署を問え。

### Security — D575: `X-Curon-*`/`X-MICIN-*`/`X-Teladoc-*` 等のオンライン診療・健康アプリ印自称が未検査

- **問題**: `X-Curon-*` (クロン)、`X-MICIN-*` (MICIN)、`X-Teladoc-*` (Teladoc)、`X-LineDoctor-*`/`X-Medley-*`/`X-EPARK-*`/`X-AskDoctors-*`/`X-HealthTap-*`/`X-MDLive-*`/`X-Amwell-*`/`X-BabylonHealth-*`/`X-Kry-*`/`X-Livi-*`/`X-AdaHealth-*`/`X-KHealth-*`/`X-PlushCare-*`/`X-BetterHelp-*`/`X-Talkspace-*`/`X-Cerebral-*`/`X-MedicalNote-*`/`X-Doctolib-*`/`X-Practo-*`/`X-Mfine-*`/`X-OkusuriTecho-*`/`X-GoodDoctor-*`/`X-EPARKKusuri-*`/`X-Ninety8Point6-*`/`X-Ro-*`/`X-Nurx-*`/`X-ForwardHealth-*`/`X-OneMedical-*`/`X-OscarHealth-*`/`X-Heal-*`/`X-Sesame-*`/`X-Parsley-*`/`X-FiNC-*`/`X-Kencom-*`/`X-PepUp-*`/`X-KaradaNote-*`/`X-Mamari-*`/`X-Ninshin-*`/`X-Conomo-*`/`X-BabyTech-*`/`X-Yonda-*`/`X-LuneLune-*`/`X-Sofi-*`/`X-KaradaKarte-*`/`X-MinnanoKaigo-*`/`X-CareMane-*`/`X-Kaigo-*` は診機の通知記録 — 送信側が書くことは自称。診察予約・処方通知・カウンセリング料金の偽装は医療詐欺の典型。(`X-CVS-*`/`X-Walgreens-*`/`X-Hims-*`/`X-Zocdoc-*` 等の医療・薬局機は既存族で検出済み)
- **修正**: `Envelope` に `telehealth_marks` + `has_telehealth_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 診印の自署を問え。

### Security — D576: `X-Komehyo-*`/`X-Daikokuya-*`/`X-StockX-*` 系の中古買取・リユース・個人間取引印自称が未検査

- **問題**: `X-Komehyo-*` (コメ兵)、`X-Daikokuya-*` (大黒屋)、`X-Nanboya-*` (なんぼや)、`X-Brandia-*`/`X-Ecoring-*`/`X-Buyma-*`/`X-Secaimon-*`/`X-TheRealReal-*`/`X-GOAT-*`/`X-Rebag-*`/`X-Fashionphile-*`/`X-Tradesy-*`/`X-Carousell-*`/`X-Wallapop-*`/`X-HardOff-*`/`X-GeoKaitori-*`/`X-Torrefa-*`/`X-SecondStreet-*`/`X-FuruhonIchiba-*`/`X-KaitoriOuji-*`/`X-NetOff-*`/`X-ValueBooks-*`/`X-OfferUp-*`/`X-VarageSale-*`/`X-Letgo-*`/`X-Shpock-*`/`X-Gumtree-*`/`X-Subito-*`/`X-Leboncoin-*`/`X-Milanuncios-*`/`X-Craigslist-*`/`X-FacebookMarket-*`/`X-MercadoLibre-*`/`X-OLX-*`/`X-Quikr-*`/`X-Bunjang-*`/`X-Joonggonara-*`/`X-Karrot-*`/`X-Fril-*`/`X-Bocho-*`/`X-Otoku-*`/`X-Kaitorikakomaru-*`/`X-Pollet-*` は買機の通知記録 — 送信側が書くことは自称。査定額提示・売買成立・発送依頼の偽装は中古売買詐欺の典型。(`X-Mercari-*`/`X-Rakuma-*`/`X-Yahoo-*`/`X-Depop-*`/`X-Vinted-*`/`X-StockX-*` 等は既存族、`X-BookOff-*`/`X-Surugaya-*`/`X-Mandarake-*` は D557/D559 で検出済み)
- **修正**: `Envelope` に `reuse_marks` + `has_reuse_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 買印の自署を問え。

### Security — D577: `X-Giant-*`/`X-Trek-*`/`X-Shimano-*` 等の自転車・サイクル印自称が未検査

- **問題**: `X-Giant-*` (Giant)、`X-Trek-*` (Trek)、`X-Shimano-*` (シマノ)、`X-Specialized-*`/`X-Cannondale-*`/`X-ScottBike-*`/`X-Bianchi-*`/`X-Pinarello-*`/`X-Merida-*`/`X-Ridley-*`/`X-FujiBike-*`/`X-GTBike-*`/`X-Campagnolo-*`/`X-SRAM-*`/`X-FSA-*`/`X-Bontrager-*`/`X-Giro-*`/`X-Kask-*`/`X-ContinentalTire-*`/`X-Vittoria-*`/`X-Maxxis-*`/`X-BridgestoneCycle-*`/`X-PanasonicCycle-*`/`X-YamahaPAS-*`/`X-AsahiCycle-*`/`X-YsRoad-*`/`X-BeckOn-*`/`X-Daichari-*`/`X-HelloCycling-*`/`X-DocomoBikeshare-*`/`X-Luup-*`/`X-Cogogo-*`/`X-CycleSpot-*`/`X-ChariChari-*`/`X-Wimby-*`/`X-Miyata-*`/`X-Marukin-*`/`X-Panaracer-*`/`X-IRC-*`/`X-Dahon-*`/`X-Tern-*`/`X-Brompton-*`/`X-Birdy-*`/`X-AlexMoulton-*`/`X-KHS-*`/`X-Brooks-*`/`X-SelleItalia-*`/`X-Fizik-*`/`X-Zipp-*` は輪機の通知記録 — 送信側が書くことは自称。偽ショップの大幅値引・在庫入荷・注文確定の偽装は自転車詐欺の典型。(`X-Nike-*`/`X-Adidas-*` 等スポーツ用品機は D529、`X-Toyota-*`/`X-Honda-*` 等は D521 で検出済み)
- **修正**: `Envelope` に `bicycle_marks` + `has_bicycle_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 輪印の自署を問え。

### Security — D572: `X-Gulliver-*`/`X-Nextage-*`/`X-Autobacs-*` 等の車買取・中古車・カー用品印自称が未検査

- **問題**: `X-Gulliver-*` (ガリバー)、`X-Nextage-*` (ネクステージ)、`X-Autobacs-*` (オートバックス)、`X-Bigmotor-*`/`X-Carseven-*`/`X-AppleKaitori-*`/`X-RabbitKaitori-*`/`X-Upos-*`/`X-YellowHat-*`/`X-James-*`/`X-Tirekan-*`/`X-Autowave-*`/`X-Carconbi-*`/`X-Navikuru-*`/`X-Carcone-*`/`X-Carsensor-*`/`X-MOTA-*`/`X-Ucarpac-*`/`X-ZubattoKaitori-*`/`X-Carview-*`/`X-Webike-*`/`X-Bikeou-*`/`X-RedBaron-*`/`X-Bikeone-*`/`X-Autotrader-*`/`X-CarsDotCom-*`/`X-Carvana-*`/`X-Vroom-*`/`X-CarGurus-*`/`X-CarMax-*`/`X-AutoScout24-*`/`X-MobileDe-*`/`X-Webmotors-*`/`X-Carsales-*`/`X-Encar-*`/`X-KCar-*`/`X-CarPrice-*`/`X-Car24-*`/`X-Cazana-*`/`X-Motory-*`/`X-Carro-*`/`X-Kavak-*`/`X-Spinny-*`/`X-Carsome-*` は売機の通知記録 — 送信側が書くことは自称。査定完了・買取金額提示・オークション結果の偽装は中古車売買詐欺の典型。(`X-Toyota-*`/`X-Honda-*` 等メーカー本体・`X-Hertz-*` 等レンタカーは D521、`X-Goo-*` は既存族で検出済み)
- **修正**: `Envelope` に `cartrade_marks` + `has_cartrade_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 売印の自署を問え。

### Security — D573: `X-JTB-*`/`X-HIS-*`/`X-KNT-*` 等の旅行代理店・ツアー催行印自称が未検査

- **問題**: `X-JTB-*` (JTB)、`X-HIS-*` (エイチ・アイ・エス)、`X-KNT-*` (近畿日本ツーリスト)、`X-ClubTourism-*`/`X-HankyuTravel-*`/`X-YomioTravel-*`/`X-NihonTravel-*`/`X-Jalpak-*`/`X-ANAHotel-*`/`X-Trip-*`/`X-Ctrip-*`/`X-GetYourGuide-*`/`X-Viator-*`/`X-Klook-*`/`X-KKday-*`/`X-Veltra-*`/`X-ActivityJapan-*`/`X-Sotoasobi-*`/`X-Japanican-*`/`X-Contiki-*`/`X-GAdventures-*`/`X-Intrepid-*`/`X-Topdeck-*`/`X-Trafalgar-*`/`X-Exodus-*`/`X-TourRadar-*`/`X-Tiqets-*`/`X-Musement-*`/`X-Headout-*`/`X-Civitatis-*`/`X-GoCity-*`/`X-Travelzoo-*`/`X-Tourlane-*`/`X-AsiaYo-*`/`X-Relux-*`/`X-Oyado-*`/`X-Yukoyuko-*`/`X-Ikkyu-*`/`X-AirTrip-*`/`X-SkyTicket-*`/`X-Ennet-*`/`X-TourHero-*`/`X-WillerTravel-*` は旅機の通知記録 — 送信側が書くことは自称。ツアー催行中止・キャンセル料請求・現地オプション当選の偽装は旅行詐欺の典型。(`X-Expedia-*`/`X-Booking-*`/`X-Agoda-*` 等 OTA は D468、`X-Jalan-*`/`X-RakutenTravel-*`/`X-Marriott-*` 等ホテル機は D535、`X-ANA-*`/`X-JAL-*` 等航空機は D513 で検出済み)
- **修正**: `Envelope` に `tour_marks` + `has_tour_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 旅印の自署を問え。

### Security — D574: `X-Vernis-*`/`X-WillUranai-*`/`X-Keen-*` 等の占い・電話占い・占星術アプリ印自称が未検査

- **問題**: `X-Vernis-*` (電話占いヴェルニ)、`X-WillUranai-*` (電話占いウィル)、`X-Keen-*` (Keen)、`X-Purely-*`/`X-Callis-*`/`X-ExciteUranai-*`/`X-Uranaikan-*`/`X-Senrigan-*`/`X-Minden-*`/`X-Urara-*`/`X-GachiUranai-*`/`X-Pixer-*`/`X-Spica-*`/`X-LineUranai-*`/`X-Destiny-*`/`X-Feel-*`/`X-Sator-*`/`X-KagamiRyuji-*`/`X-Getters-*`/`X-HoshiHitomi-*`/`X-SuishoTamako-*`/`X-Shiitake-*`/`X-HosokiKazuko-*`/`X-DrKopa-*`/`X-LeeKuan-*`/`X-Kasamba-*`/`X-CaliforniaPsychics-*`/`X-PsychicSource-*`/`X-PurpleGarden-*`/`X-BitWine-*`/`X-AskNow-*`/`X-PathForward-*`/`X-AstroYogi-*`/`X-AstroGuide-*`/`X-Nebula-*`/`X-Sanctuary-*`/`X-CoStar-*`/`X-Chani-*`/`X-TimePassages-*`/`X-ThePattern-*`/`X-AstrologyZone-*`/`X-Tarot-*`/`X-Voyance-*`/`X-Wengo-*` は鑑機の通知記録 — 送信側が書くことは自称。「呪い解除」「高額鑑定」「先祖の因縁」勧誘の偽装は占い詐欺の典型。
- **修正**: `Envelope` に `fortune_marks` + `has_fortune_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 鑑印の自署を問え。

### Performance / Fixed — D570: `has_*_marks` 155 関数がヘッダのためだけに全文を複製していた

- **問題**: `kaname-render` の `has_*_marks` 155 関数がそれぞれメッセージ全体 (最大 100 MB) を `from_utf8_lossy` + `to_ascii_lowercase` で複製してからヘッダだけを見ており、1 回の `parse()` で約 310 回の全文コピーが起きていた。さらに空行判定が `\r\n\r\n` のみで、LF 改行の `.eml` では本文全体がヘッダ扱いされ本文行で誤検出していた。
- **修正**: `header_section()` (CRLF/LF 両対応) を追加し、`parse()` で一度だけ切り出したヘッダ部を渡す。関数本体・シグネチャは不変。回帰テスト3件、`static-check.sh` 検査11 (`parse()` 内の `has_*_marks(raw)` を禁止) を追加。

### Recorded — D571: ブランド「自称」印が From ドメインを見ないため正規メールでも警告 (未修正)

- `X-<Brand>-*` ヘッダの存在だけで警告するため、ブランド自身の正規メールでも「自称の兆候」が出る。製品判断が必要なため記録のみ (詳細: `docs/gap-analysis.md` D571)。

### Security — D567: `X-VISA-*`/`X-Amex-*`/`X-Saison-*` 等のクレジットカード印自称が未検査

- **問題**: `X-VISA-*` (Visa)、`X-Amex-*` (アメックス)、`X-Saison-*` (セゾンカード)、`X-Mastercard-*`/`X-Diners-*`/`X-Discover-*`/`X-RakutenCard-*`/`X-SMBCCard-*`/`X-JACCS-*`/`X-Orico-*`/`X-Nicos-*`/`X-DCCard-*`/`X-UCCard-*`/`X-Aplus-*`/`X-Jacks-*`/`X-PocketCard-*`/`X-ViewCard-*`/`X-VJA-*`/`X-AmericanExpress-*`/`X-ChaseCard-*`/`X-CitiCard-*`/`X-BofACard-*`/`X-WellsFargoCard-*`/`X-USAA-*`/`X-CommBankCard-*`/`X-ANZCard-*`/`X-NABCard-*`/`X-WestpacCard-*`/`X-RBCard-*`/`X-TDCard-*`/`X-BMO-*`/`X-MBNA-*`/`X-VirginMoney-*`/`X-Halifax-*`/`X-Lloyds-*`/`X-SantanderCard-*`/`X-NationwideCard-*`/`X-Barclaycard-*`/`X-MonzoCard-*`/`X-RevolutCard-*`/`X-Epos-*`/`X-ToyotaFinance-*`/`X-MercedesBenzCard-*`/`X-BMWCard-*` は札機の通知記録 — 送信側が書くことは自称。カード利用停止・身に覚えのない決済の偽装はクレカ詐欺の典型。(`X-JCB-*`/`X-UnionPay-*`/`X-Scotiabank-*` は既存族で検出済み)
- **修正**: `Envelope` に `creditcard_marks` + `has_creditcard_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 札印の自署を問え。

### Security — D568: `X-TPoint-*`/`X-Suica-*`/`X-Ponta-*` 等のポイント・交通系 IC・QR 決済印自称が未検査

- **問題**: `X-TPoint-*` (Tポイント)、`X-Suica-*` (Suica)、`X-Ponta-*` (Ponta)、`X-DPoint-*`/`X-RakutenPoint-*`/`X-WAON-*`/`X-Nanaco-*`/`X-Edy-*`/`X-ICOCA-*`/`X-PASMO-*`/`X-Kitaca-*`/`X-TOICA-*`/`X-Manaca-*`/`X-SUGOCA-*`/`X-Nimoca-*`/`X-Hayakaken-*`/`X-Majica-*`/`X-JREPoint-*`/`X-RakutenEdy-*`/`X-VPoint-*`/`X-FamiPay-*`/`X-QUICPay-*`/`X-ID-*`/`X-ApplePay-*`/`X-GooglePay-*`/`X-AuPay-*`/`X-Merpay-*`/`X-LinePay-*`/`X-DBarai-*`/`X-RPay-*`/`X-SmartPay-*`/`X-NetMile-*`/`X-GiftMall-*`/`X-Pochi-*`/`X-Gilpe-*`/`X-Posca-*`/`X-Moneyk-*`/`X-Kimisuta-*`/`X-Satore-*` は点機の通知記録 — 送信側が書くことは自称。ポイント失効・チャージ増量偽装はポイント詐欺の典型。(`X-PayPay-*`/`X-Origami-*` は既存族で検出済み)
- **修正**: `Envelope` に `pointcard_marks` + `has_pointcard_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 点印の自署を問え。

### Security — D569: `X-Airalo-*`/`X-Holafly-*`/`X-Ubigi-*` 等の eSIM・旅行 SIM 印自称が未検査

- **問題**: `X-Airalo-*` (Airalo)、`X-Holafly-*` (Holafly)、`X-Ubigi-*` (Ubigi)、`X-Truphone-*`/`X-AloSIM-*`/`X-Nomad-*`/`X-Saily-*`/`X-Jetpac-*`/`X-BNesim-*`/`X-Flexiroam-*`/`X-GigSky-*`/`X-MayaMobile-*`/`X-Airhub-*`/`X-SIM2Fly-*`/`X-OrangeESIM-*`/`X-ETravelSim-*`/`X-IIJeSIM-*`/`X-RakutenSim-*`/`X-WorldESIM-*`/`X-ESIMDB-*`/`X-E4ESIM-*`/`X-ESIM2Go-*`/`X-Instabridge-*`/`X-RedTeago-*` は仮機の通知記録 — 送信側が書くことは自称。海外データプラン・有効期限切れ偽装は eSIM 詐欺の典型。(`X-Docomo-*`/`X-KDDI-*`/`X-SoftBank-*` 等のキャリア本体は D511 で検出済み)
- **修正**: `Envelope` に `esim_marks` + `has_esim_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 仮印の自署を問え。


### Security — D564: `X-FMarinos-*`/`X-Dodgers-*`/`X-ManUnited-*` 等のプロスポーツチーム印自称が未検査

- **問題**: `X-FMarinos-*` (横浜F・マリノス)、`X-Dodgers-*` (ドジャース)、`X-ManUnited-*` (マンチェスター・ユナイテッド)、`X-UrawaReds-*`/`X-Antlers-*`/`X-Frontale-*`/`X-FCTokyo-*`/`X-Gamba-*`/`X-Cerezo-*`/`X-Grampus-*`/`X-Sanfrecce-*`/`X-Vissel-*`/`X-Reysol-*`/`X-SPulse-*`/`X-Jubilo-*`/`X-Consadole-*`/`X-Vegalta-*`/`X-Montedio-*`/`X-Albirex-*`/`X-Bellmare-*`/`X-Sagan-*`/`X-Avispa-*`/`X-Trinita-*`/`X-Verdy-*`/`X-Zelvia-*`/`X-KyotoSanga-*`/`X-Fagiano-*`/`X-Zweigen-*`/`X-Roasso-*`/`X-Giravanz-*`/`X-Varen-*`/`X-Kamatamare-*`/`X-FCRyukyu-*`/`X-Yankees-*`/`X-Giants-*`/`X-Tigers-*`/`X-RedSox-*`/`X-Cubs-*`/`X-Mets-*`/`X-Phillies-*`/`X-Padres-*`/`X-Mariners-*`/`X-Liverpool-*`/`X-Arsenal-*`/`X-Chelsea-*`/`X-Tottenham-*`/`X-ManCity-*`/`X-Newcastle-*`/`X-AstonVilla-*`/`X-WestHam-*`/`X-Everton-*`/`X-Leicester-*`/`X-Brighton-*`/`X-Fulham-*`/`X-Brentford-*`/`X-CrystalPalace-*`/`X-Wolves-*`/`X-RealMadrid-*`/`X-Barcelona-*`/`X-Atletico-*`/`X-Bayern-*`/`X-Dortmund-*`/`X-PSG-*`/`X-Juventus-*`/`X-ACMilan-*`/`X-Inter-*`/`X-ASRoma-*`/`X-Napoli-*`/`X-Ajax-*`/`X-Porto-*`/`X-Benfica-*`/`X-Celtic-*`/`X-Rangers-*`/`X-Feyenoord-*` は球機の通知記録 — 送信側が書くことは自称。チケット・グッズ当選偽装はスポーツ詐欺の典型。(`X-Nike-*`/`X-Adidas-*` 等のスポーツ用品機は D529 で検出済み)
- **修正**: `Envelope` に `sports_team_marks` + `has_sports_team_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 球印の自署を問え。

### Security — D565: `X-Zoff-*`/`X-JINS-*`/`X-OWNDAYS-*` 等の眼鏡・コンタクト・補聴器印自称が未検査

- **問題**: `X-Zoff-*` (Zoff)、`X-JINS-*` (JINS)、`X-OWNDAYS-*` (OWNDAYS)、`X-ParisMiki-*`/`X-WarbyParker-*`/`X-LensCrafters-*`/`X-Specsavers-*`/`X-GrandVision-*`/`X-MeganeIchiba-*`/`X-BJClassic-*`/`X-EYEVAN-*`/`X-Masunaga-*`/`X-Kaneko-*`/`X-OliverPeoples-*`/`X-RayBan-*`/`X-Oakley-*`/`X-Persol-*`/`X-Bolon-*`/`X-GentleMonster-*`/`X-SeeConcept-*`/`X-Rionet-*`/`X-Mirall-*`/`X-Sonova-*`/`X-Phonak-*`/`X-Oticon-*`/`X-ReSound-*`/`X-Signia-*`/`X-Widex-*`/`X-Starkey-*`/`X-Unitron-*`/`X-Bernafon-*` は眼機の通知記録 — 送信側が書くことは自称。視力検査・度数更新偽装は眼鏡詐欺の典型。
- **修正**: `Envelope` に `optical_marks` + `has_optical_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 眼印の自署を問え。

### Security — D566: `X-JMA-*`/`X-WeatherNews-*`/`X-Yurekuru-*` 等の気象・地震・防災印自称が未検査

- **問題**: `X-JMA-*` (気象庁)、`X-WeatherNews-*` (ウェザーニュース)、`X-Yurekuru-*` (ゆれくるコール)、`X-WeatherMap-*`/`X-TenkiJP-*`/`X-LifeRanger-*`/`X-NERV-*`/`X-HazardMap-*`/`X-BousaiSoku-*`/`X-YahooBousai-*`/`X-AccuWeather-*`/`X-WeatherChannel-*`/`X-WUnderground-*`/`X-MetOffice-*`/`X-BOM-*`/`X-Meteoblue-*`/`X-Windy-*`/`X-SoraNav-*`/`X-StormShield-*`/`X-IAlert-*`/`X-JAlert-*`/`X-MetService-*`/`X-KNMI-*`/`X-DWD-*`/`X-Meteociel-*`/`X-YR-*`/`X-Ventusky-*`/`X-RainViewer-*`/`X-RadarScope-*`/`X-WeatherBug-*`/`X-Carrot-*`/`X-FlowX-*`/`X-MyRadar-*` は防機の通知記録 — 送信側が書くことは自称。緊急速報・避難指示偽装は災害詐欺の典型。(`X-FEMA-*` 等の政府機関は D518 で検出済み)
- **修正**: `Envelope` に `disaster_marks` + `has_disaster_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 防印の自署を問え。


### Security — D561: `X-Anicom-*`/`X-iPet-*`/`X-Rover-*` 等のペット保険・ペットサービス印自称が未検査

- **問題**: `X-Anicom-*` (アニコム)、`X-iPet-*` (アイペット)、`X-Rover-*` (Rover)、`X-FPC-*`/`X-PSInsurance-*`/`X-PetFamily-*`/`X-RakutenPet-*`/`X-Wag-*`/`X-Banfield-*`/`X-VCA-*`/`X-BluePearl-*`/`X-Medivet-*`/`X-Petplan-*`/`X-Trupanion-*`/`X-HealthyPaws-*`/`X-EmbracePet-*`/`X-FetchPet-*`/`X-LemonadePet-*`/`X-PetsBest-*`/`X-SpotPet-*`/`X-Figo-*`/`X-ManyPets-*`/`X-Waggel-*`/`X-PetsOkay-*`/`X-PetsitterSOS-*`/`X-DoggyBox-*`/`X-CocoGourmet-*`/`X-PetOla-*`/`X-PETOKOTO-*`/`X-Peco-*` は愛機の通知記録 — 送信側が書くことは自称。保険金・手術費用偽装はペット保険詐欺の典型。(`X-PetSmart-*`/`X-Chewy-*`/`X-Zooplus-*` 等のペット用品店は D533 で検出済み)
- **修正**: `Envelope` に `pet_service_marks` + `has_pet_service_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 愛印の自署を問え。

### Security — D562: `X-Zexy-*`/`X-IBJ-*`/`X-Onet-*` 等の結婚式場・結婚相談所印自称が未検査

- **問題**: `X-Zexy-*` (ゼクシィ)、`X-IBJ-*` (IBJ)、`X-Onet-*` (オーネット)、`X-Hanayume-*`/`X-WeddingPark-*`/`X-BridalNet-*`/`X-MinnaWedding-*`/`X-Maricuru-*`/`X-Anniversaire-*`/`X-Escreet-*`/`X-BleuBlanc-*`/`X-TGN-*`/`X-BestBridal-*`/`X-Claudia-*`/`X-PlanDoSee-*`/`X-HappoEn-*`/`X-MeijiKinenkan-*`/`X-Zwei-*`/`X-PartnerAgent-*`/`X-Nozze-*`/`X-Fiori-*`/`X-SanMarie-*`/`X-EnKonkatsu-*`/`X-ZexyEng-*`/`X-Smaridge-*`/`X-Marrish-*`/`X-Infinity-*`/`X-Naco-*` は婚機の通知記録 — 送信側が書くことは自称。式場見学・お見合い料金偽装はブライダル詐欺の典型。(`X-Minavi-*`/`X-Gurunavi-*` は D482/D555 で検出済み)
- **修正**: `Envelope` に `bridal_marks` + `has_bridal_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 婚印の自署を問え。

### Security — D563: `X-UenoZoo-*`/`X-Kaiyukan-*`/`X-Churaumi-*` 等の動物園・水族館・牧場印自称が未検査

- **問題**: `X-UenoZoo-*` (上野動物園)、`X-Kaiyukan-*` (海遊館)、`X-Churaumi-*` (美ら海水族館)、`X-Asahiyama-*`/`X-TamaZoo-*`/`X-HigashiyamaZoo-*`/`X-TennojiZoo-*`/`X-AdventureWorld-*`/`X-Nasu-*`/`X-MotherBokujo-*`/`X-TobuZoo-*`/`X-Zoorasia-*`/`X-YokohamaZoo-*`/`X-Nonhoi-*`/`X-Sunshine-*`/`X-Nagoyako-*`/`X-Sumasui-*`/`X-Kamogawa-*`/`X-AquaPark-*`/`X-Sumida-*`/`X-Enosui-*`/`X-Kasai-*`/`X-Toba-*`/`X-Kaiyokan-*`/`X-Kushimoto-*`/`X-AnimalPark-*` は園機の通知記録 — 送信側が書くことは自称。チケット・イベント当選偽装は動物園詐欺の典型。(`X-USJ-*`/`X-Disney-*`/`X-Legoland-*` 等のテーマパークは D536 で検出済み)
- **修正**: `Envelope` に `zoo_marks` + `has_zoo_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 園印の自署を問え。


### Security — D558: `X-LEGO-*`/`X-TakaraTomy-*`/`X-Bandai-*` 等の玩具・フィギュア・TCG 印自称が未検査

- **問題**: `X-LEGO-*` (LEGO)、`X-TakaraTomy-*` (タカラトミー)、`X-Bandai-*` (バンダイ)、`X-GoodSmile-*`/`X-Kotobukiya-*`/`X-MegaHouse-*`/`X-Alter-*`/`X-PhatCompany-*`/`X-FREEing-*`/`X-QuesQ-*`/`X-Revolve-*`/`X-PopParade-*`/`X-Prime1Studio-*`/`X-HotToys-*`/`X-Sideshow-*`/`X-Funko-*`/`X-POPMART-*`/`X-Volks-*`/`X-Tamiya-*`/`X-Hasegawa-*`/`X-Aoshima-*`/`X-Fujimi-*`/`X-Wave-*`/`X-Plarail-*`/`X-Tomica-*`/`X-Licca-*`/`X-Sylvanian-*`/`X-Beyblade-*`/`X-DuelMasters-*`/`X-YuGiOh-*`/`X-MTG-*`/`X-Wizards-*`/`X-PokemonTCG-*`/`X-Cardfight-*`/`X-Bushiroad-*`/`X-WIXOSS-*`/`X-WeissSchwarz-*`/`X-OnePieceCard-*`/`X-Hasbro-*`/`X-Mattel-*`/`X-FisherPrice-*`/`X-Nerf-*`/`X-Barbie-*`/`X-HotWheels-*`/`X-Tamagotchi-*`/`X-Amiibo-*`/`X-ReBirth-*`/`X-Vividz-*`/`X-Playmobil-*`/`X-LOLSurprise-*`/`X-Matchbox-*`/`X-FunkoPop-*`/`X-Nendoroid-*`/`X-Figma-*`/`X-SHFiguarts-*`/`X-RobotDamashii-*`/`X-MetalBuild-*`/`X-SOC-*`/`X-Chogokin-*`/`X-HG-*`/`X-MG-*`/`X-PG-*`/`X-RG-*`/`X-EG-*`/`X-SD-*` は玩機の通知記録 — 送信側が書くことは自称。限定抽選・予約開始偽装は玩具詐欺の典型。(`X-BandaiNamco-*` 等のゲーム機は D473 で検出済み)
- **修正**: `Envelope` に `toy_marks` + `has_toy_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 玩印の自署を問え。

### Security — D559: `X-Amiami-*`/`X-Surugaya-*`/`X-Mandarake-*` 等のホビーショップ・同人・カードショップ・プライズ印自称が未検査

- **問題**: `X-Amiami-*` (あみあみ)、`X-Surugaya-*` (駿河屋)、`X-Mandarake-*` (まんだらけ)、`X-YellowSubmarine-*`/`X-CardLabo-*`/`X-RyuNoShippo-*`/`X-FullComp-*`/`X-Canaveral-*`/`X-Clove-*`/`X-Magi-*`/`X-Hareruya-*`/`X-Toranoana-*`/`X-Melonbooks-*`/`X-GeeStore-*`/`X-HobbySearch-*`/`X-AsobiStore-*`/`X-PremiumBandai-*`/`X-HobbyJapan-*`/`X-KotobukiyaShop-*`/`X-Daiki-*`/`X-OrchidSeed-*`/`X-AlphaMax-*`/`X-WingScale-*`/`X-UnionCreative-*`/`X-Myethos-*`/`X-ApexToys-*`/`X-GSAS-*`/`X-BellFine-*`/`X-Furyu-*`/`X-Taito-*`/`X-SegaPrize-*`/`X-Banpresto-*`/`X-BPrize-*`/`X-IchibanKuji-*`/`X-CharaAni-*`/`X-AniplexPlus-*`/`X-KadokawaStore-*`/`X-HobbyStock-*` は趣機の通知記録 — 送信側が書くことは自称。在庫復活・抽選当選偽装はホビー詐欺の典型。
- **修正**: `Envelope` に `hobby_marks` + `has_hobby_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 趣印の自署を問え。

### Security — D560: `X-Takashimaya-*`/`X-Mitsukoshi-*`/`X-Parco-*` 等の百貨店・アウトレット・商業施設印自称が未検査

- **問題**: `X-Takashimaya-*` (高島屋)、`X-Mitsukoshi-*` (三越)、`X-Parco-*` (PARCO)、`X-Isetan-*`/`X-Daimaru-*`/`X-Matsuzakaya-*`/`X-Sogo-*`/`X-Lumine-*`/`X-Marui-*`/`X-Laforet-*`/`X-Atre-*`/`X-Kitte-*`/`X-GinzaSix-*`/`X-Midtown-*`/`X-RoppongiHills-*`/`X-Solamachi-*`/`X-Lucua-*`/`X-GrandFront-*`/`X-Umeda-*`/`X-NambaParks-*`/`X-CanalCity-*`/`X-MitsuiOutlet-*`/`X-PremiumOutlets-*`/`X-Gotemba-*`/`X-Rinku-*`/`X-Sano-*`/`X-Kisarazu-*`/`X-Iruma-*`/`X-Fukaya-*`/`X-Shisui-*`/`X-Toki-*`/`X-JazzDream-*`/`X-SendaiPort-*`/`X-Tosu-*`/`X-KobeSanda-*`/`X-Tarumi-*`/`X-Marinepia-*`/`X-MinamiOsawa-*`/`X-Oarai-*`/`X-YokohamaBayside-*`/`X-Toua-*`/`X-OutletPark-*` は商機の通知記録 — 送信側が書くことは自称。外商・ポイント失効偽装は百貨店詐欺の典型。(`X-AEON-*`/`X-Tokyu-*` 等の小売・鉄道系は D522/D525 で検出済み)
- **修正**: `Envelope` に `department_marks` + `has_department_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 商印の自署を問え。


### Security — D555: `X-HelloFresh-*`/`X-Oisix-*`/`X-Tabelog-*` 等のミールキット・食材宅配・グルメメディア印自称が未検査

- **問題**: `X-HelloFresh-*` (HelloFresh)、`X-Oisix-*` (オイシックス)、`X-Tabelog-*` (食べログ)、`X-BlueApron-*`/`X-Gousto-*`/`X-MarleySpoon-*`/`X-EveryPlate-*`/`X-Freshly-*`/`X-Factor75-*`/`X-HomeChef-*`/`X-PurpleCarrot-*`/`X-Sakara-*`/`X-DailyHarvest-*`/`X-Hungryroot-*`/`X-nosh-*`/`X-Watami-*`/`X-RadishBooya-*`/`X-CoopDeli-*`/`X-PalSystem-*`/`X-DaichiWoMamoru-*`/`X-Gurunavi-*`/`X-HotPepper-*`/`X-Retty-*`/`X-Favy-*`/`X-Funpay-*`/`X-Luckey-*`/`X-Futto-*` は膳機の通知記録 — 送信側が書くことは自称。定期購入・解約・クーポン偽装は食材宅配詐欺の典型。
- **修正**: `Envelope` に `mealkit_marks` + `has_mealkit_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 膳印の自署を問え。

### Security — D556: `X-RedCross-*`/`X-Satofuru-*`/`X-UNICEF-*` 等の寄付・ふるさと納税・NPO 印自称が未検査

- **問題**: `X-RedCross-*` (赤十字)、`X-Satofuru-*` (さとふる)、`X-UNICEF-*` (UNICEF)、`X-WWF-*`/`X-PlanIntl-*`/`X-MSF-*`/`X-SaveTheChildren-*`/`X-Care-*`/`X-Oxfam-*`/`X-Amnesty-*`/`X-JapanPlatform-*`/`X-AAR-*`/`X-Peace-*`/`X-ICRC-*`/`X-UNDP-*`/`X-Furunavi-*`/`X-FuruChoice-*`/`X-FurusatoMall-*`/`X-AnaFurusato-*`/`X-FuruPo-*`/`X-RakutenFurusato-*`/`X-FuruLabo-*`/`X-FurusatoPremier-*`/`X-JREMallFurusato-*`/`X-AuFurusato-*`/`X-YahooFurusato-*`/`X-DocomoFurusato-*` は善機の通知記録 — 送信側が書くことは自称。災害寄付・返礼品偽装は寄付詐欺の典型。(`X-GoFundMe-*`/`X-Kickstarter-*`/`X-Indiegogo-*` 等のクラウドファンディング機は D479 で検出済み)
- **修正**: `Envelope` に `charity_marks` + `has_charity_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 善印の自署を問え。

### Security — D557: `X-Piccoma-*`/`X-CMOA-*`/`X-Kodansha-*` 等の漫画・電子書籍・書店・出版社印自称が未検査

- **問題**: `X-Piccoma-*` (ピッコマ)、`X-CMOA-*` (コミックシーモア)、`X-Kodansha-*` (講談社)、`X-Webtoon-*`/`X-MechaComi-*`/`X-Renta-*`/`X-BookLive-*`/`X-AmebaManga-*`/`X-MangaKingdom-*`/`X-DMMBooks-*`/`X-Honto-*`/`X-Kinokuniya-*`/`X-Maruzen-*`/`X-Junkudo-*`/`X-BookOff-*`/`X-TsutayaBook-*`/`X-Yurindo-*`/`X-Sanseido-*`/`X-Miraiya-*`/`X-Bunkyo-*`/`X-Kumazawa-*`/`X-Shueisha-*`/`X-Shogakukan-*`/`X-Kadokawa-*`/`X-Akita-*`/`X-Hakusensha-*`/`X-Takeshobo-*`/`X-Leed-*`/`X-NihonBungeisha-*`/`X-Bunshun-*`/`X-Core-*`/`X-Ohta-*`/`X-ShonenJump-*` は書機の通知記録 — 送信側が書くことは自称。ポイント失効・新刊案内偽装は書籍詐欺の典型。
- **修正**: `Envelope` に `manga_marks` + `has_manga_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 書印の自署を問え。


### Security — D552: `X-Rolex-*`/`X-Cartier-*`/`X-Hermes-*` 等の宝飾・時計・高級ブランド印自称が未検査

- **問題**: `X-Rolex-*` (Rolex)、`X-Cartier-*` (Cartier)、`X-Hermes-*` (Hermes)、`X-Omega-*`/`X-PatekPhilippe-*`/`X-TAGHeuer-*`/`X-Breitling-*`/`X-IWC-*`/`X-GrandSeiko-*`/`X-Tiffany-*`/`X-Bulgari-*`/`X-VanCleef-*`/`X-HarryWinston-*`/`X-Mikimoto-*`/`X-Tasaki-*`/`X-4C-*`/`X-Swarovski-*`/`X-LouisVuitton-*`/`X-Gucci-*`/`X-Prada-*`/`X-Chanel-*`/`X-Dior-*`/`X-Burberry-*`/`X-Coach-*`/`X-Fendi-*`/`X-Loewe-*`/`X-Celine-*`/`X-Balenciaga-*`/`X-Bottega-*`/`X-SaintLaurent-*`/`X-Givenchy-*`/`X-Valentino-*`/`X-Ferragamo-*`/`X-Bally-*`/`X-Tods-*`/`X-Montblanc-*`/`X-Chaumet-*`/`X-Boucheron-*`/`X-Piaget-*`/`X-Chopard-*`/`X-Jaeger-*`/`X-Audemars-*`/`X-RichardMille-*`/`X-Hublot-*`/`X-Zenith-*`/`X-Tudor-*`/`X-Longines-*`/`X-Orient-*`/`X-Tissot-*` は奢機の通知記録 — 送信側が書くことは自称。修理・買取・会員特典偽装は高級品詐欺の典型。(`X-Pandora-*`/`X-Seiko-*`/`X-Citizen-*`/`X-Casio-*` は D493/D496 で検出済み)
- **修正**: `Envelope` に `luxury_marks` + `has_luxury_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 奢印の自署を問え。

### Security — D553: `X-Dentsu-*`/`X-Hakuhodo-*`/`X-PRTIMES-*` 等の広告代理店・PR・芸能事務所印自称が未検査

- **問題**: `X-Dentsu-*` (電通)、`X-Hakuhodo-*` (博報堂)、`X-PRTIMES-*` (PR TIMES)、`X-ADK-*`/`X-WPP-*`/`X-Omnicom-*`/`X-Publicis-*`/`X-IPG-*`/`X-Havas-*`/`X-CyberAgent-*`/`X-Septeni-*`/`X-DentsuPR-*`/`X-Daiko-*`/`X-Oriental-*`/`X-Beacon-*`/`X-Coconuts-*`/`X-DaiichiKikaku-*`/`X-Asatsu-*`/`X-Cerebrum-*`/`X-Adire-*`/`X-Cremo-*`/`X-Tohokushinsha-*`/`X-AdComms-*`/`X-ShochikuGeino-*`/`X-HoriPro-*`/`X-Avex-*`/`X-Amuse-*`/`X-Stardust-*`/`X-Burning-*`/`X-KDash-*`/`X-Yoshimoto-*`/`X-Oscar-*`/`X-Kenon-*`/`X-JapanMusic-*`/`X-Igosso-*` は広機の通知記録 — 送信側が書くことは自称。広告掲載・芸能スカウト偽装は広告詐欺の典型。
- **修正**: `Envelope` に `advertising_marks` + `has_advertising_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 広印の自署を問え。

### Security — D554: `X-YokohamaBank-*`/`X-Shinkin-*`/`X-JABank-*` 等の地方銀行・信用金庫・労金・JA・政府系金融印自称が未検査

- **問題**: `X-YokohamaBank-*` (横浜銀行)、`X-Shinkin-*` (信用金庫)、`X-JABank-*` (JA バンク)、`X-ChibaBank-*`/`X-FukuokaBank-*`/`X-ShizuokaBank-*`/`X-SurugaBank-*`/`X-KyotoBank-*`/`X-KansaiMirai-*`/`X-Ikeda-*`/`X-NishiNihonCity-*`/`X-HiroshimaBank-*`/`X-114Bank-*`/`X-IyoBank-*`/`X-ShikokuBank-*`/`X-YamaguchiBank-*`/`X-Momiji-*`/`X-HokkaidoBank-*`/`X-Hokuto-*`/`X-Tottori-*`/`X-SanInGodo-*`/`X-77Bank-*`/`X-TohoBank-*`/`X-GunmaBank-*`/`X-AshikagaBank-*`/`X-JoyoBank-*`/`X-TsukubaBank-*`/`X-MusashinoBank-*`/`X-Kiraboshi-*`/`X-DaitoBank-*`/`X-TowaBank-*`/`X-TochigiBank-*`/`X-KochiBank-*`/`X-MiyazakiBank-*`/`X-OkinawaBank-*`/`X-RyukyuBank-*`/`X-Rokin-*`/`X-Shinkumi-*`/`X-Norinchukin-*`/`X-ShokoChukin-*`/`X-JFC-*`/`X-Shinsei-*`/`X-Aozora-*` は地機の通知記録 — 送信側が書くことは自称。口座凍結・振込確認の偽装は地域金融詐欺の典型。(`X-MUFG-*`/`X-SMBC-*`/`X-Mizuho-*`/`X-SevenBank-*`/`X-AeonBank-*` 等の大手・ネット銀行は D514 で検出済み)
- **修正**: `Envelope` に `regional_bank_marks` + `has_regional_bank_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 地印の自署を問え。


### Security — D549: `X-NHK-*`/`X-BBC-*`/`X-ESPN-*` 等の放送局・チャンネル印自称が未検査

- **問題**: `X-NHK-*` (NHK)、`X-BBC-*` (BBC)、`X-ESPN-*` (ESPN)、`X-NTV-*`/`X-TBS-*`/`X-FujiTV-*`/`X-TVAsahi-*`/`X-TVTokyo-*`/`X-WOWOW-*`/`X-CNN-*`/`X-FOX-*`/`X-ABC-*`/`X-CBS-*`/`X-NBC-*`/`X-PBS-*`/`X-CBC-*`/`X-ARD-*`/`X-ZDF-*`/`X-RAI-*`/`X-FranceTV-*`/`X-KBS-*`/`X-MBC-*`/`X-JTBC-*`/`X-tvN-*`/`X-NHKWorld-*`/`X-HBO-*`/`X-Cinemax-*`/`X-Showtime-*`/`X-Starz-*`/`X-AMC-*`/`X-FX-*`/`X-Cartoon-*`/`X-Nickelodeon-*`/`X-Discovery-*`/`X-NationalGeographic-*`/`X-HistoryChannel-*`/`X-AnimalPlanet-*` は放機の通知記録 — 送信側が書くことは自称。受信料・番組案内偽装は放送詐欺の典型。(`X-ABEMA-*`/`X-TVer-*`/`X-Netflix-*` 等の配信機は D516、`X-Sky-*` は D511、`X-OCN-*` は D426 で検出済み)
- **修正**: `Envelope` に `broadcast_marks` + `has_broadcast_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 放印の自署を問え。

### Security — D550: `X-Nikkei-*`/`X-Reuters-*`/`X-Kyodo-*` 等の新聞・通信社・経済・スポーツメディア印自称が未検査

- **問題**: `X-Nikkei-*` (日本経済新聞)、`X-Reuters-*` (Reuters)、`X-Kyodo-*` (共同通信)、`X-Asahi-*`/`X-Mainichi-*`/`X-Yomiuri-*`/`X-Sankei-*`/`X-NYT-*`/`X-WSJ-*`/`X-WashingtonPost-*`/`X-Times-*`/`X-APNews-*`/`X-AFP-*`/`X-Jiji-*`/`X-Bloomberg-*`/`X-DPA-*`/`X-PA-*`/`X-NewsCorp-*`/`X-NikkeiBP-*`/`X-Diamond-*`/`X-President-*`/`X-ToyoKeizai-*`/`X-Zakzak-*`/`X-TokyoSports-*`/`X-BizJournals-*`/`X-NikkanSports-*`/`X-SportsNippon-*`/`X-Hochi-*`/`X-Sanspo-*`/`X-Sponichi-*`/`X-DailySports-*` は報機の通知記録 — 送信側が書くことは自称。購読料・記事案内偽装は報道詐欺の典型。(`X-Guardian-*` は D489 で検出済み)
- **修正**: `Envelope` に `newspaper_marks` + `has_newspaper_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 報印の自署を問え。

### Security — D551: `X-Nestle-*`/`X-Suntory-*`/`X-Nissin-*` 等の食品・飲料・酒・菓子メーカー印自称が未検査

- **問題**: `X-Nestle-*` (Nestle)、`X-Suntory-*` (サントリー)、`X-Nissin-*` (日清食品)、`X-Danone-*`/`X-Fonterra-*`/`X-Kirin-*`/`X-AsahiBeer-*`/`X-Meiji-*`/`X-Morinaga-*`/`X-Ajinomoto-*`/`X-Nippn-*`/`X-Nichirei-*`/`X-Itoham-*`/`X-NihonHam-*`/`X-Yakult-*`/`X-Calbee-*`/`X-Kewpie-*`/`X-House-*`/`X-Kikkoman-*`/`X-ToyoSuisan-*`/`X-Glico-*`/`X-Lotte-*`/`X-SnowMeg-*`/`X-PrimaHam-*`/`X-Kameda-*`/`X-Nongshim-*`/`X-CJ-*`/`X-Ottogi-*`/`X-Heinz-*`/`X-Kraft-*`/`X-FritoLay-*`/`X-PepsiCo-*`/`X-CocaCola-*`/`X-Mars-*`/`X-Hershey-*`/`X-Lindt-*`/`X-Godiva-*`/`X-Royce-*`/`X-Morozoff-*`/`X-YokuMoku-*`/`X-Budweiser-*`/`X-Heineken-*`/`X-Carlsberg-*`/`X-Guinness-*`/`X-Stella-*`/`X-Corona-*`/`X-Peroni-*`/`X-SapporoBeer-*`/`X-Ebisu-*`/`X-JimBeam-*`/`X-JackDaniels-*`/`X-Absolut-*`/`X-Smirnoff-*`/`X-Bacardi-*`/`X-JohnnieWalker-*`/`X-Chivas-*`/`X-Ballantines-*`/`X-Glenfiddich-*`/`X-Nikka-*`/`X-Yamazaki-*`/`X-Hibiki-*`/`X-Hakushu-*`/`X-JT-*` は食機の通知記録 — 送信側が書くことは自称。懸賞・モニター募集偽装は食品詐欺の典型。(`X-Unilever-*`/`X-PG-*` 等の日用品機は D533 で検出済み)
- **修正**: `Envelope` に `food_marks` + `has_food_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 食印の自署を問え。


### Security — D546: `X-Deloitte-*`/`X-KPMG-*`/`X-McKinsey-*` 等の監査・コンサル・格付印自称が未検査

- **問題**: `X-Deloitte-*` (Deloitte)、`X-KPMG-*` (KPMG)、`X-McKinsey-*` (McKinsey)、`X-PwC-*`/`X-EY-*`/`X-BCG-*`/`X-Bain-*`/`X-Accenture-*`/`X-Capgemini-*`/`X-Cognizant-*`/`X-Infosys-*`/`X-TCS-*`/`X-Wipro-*`/`X-GrantThornton-*`/`X-BDO-*`/`X-RSM-*`/`X-Mazars-*`/`X-Crowe-*`/`X-BakerTilly-*`/`X-Protiviti-*`/`X-Mercer-*`/`X-WTW-*`/`X-MarshMcLennan-*`/`X-Gartner-*`/`X-Forrester-*`/`X-IDC-*`/`X-Moodys-*`/`X-Fitch-*`/`X-SPGlobal-*`/`X-RI-*`/`X-JCR-*`/`X-EisnerAmper-*`/`X-MossAdams-*` は監機の通知記録 — 送信側が書くことは自称。監査通知・格付変更の偽装は金融 BEC の典型。(`X-Aon-*` は D519 で検出済み)
- **修正**: `Envelope` に `accounting_marks` + `has_accounting_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 監印の自署を問え。

### Security — D547: `X-Bet365-*`/`X-toto-*`/`X-VeraJohn-*` 等の賭博・ブックメーカー・カジノ印自称が未検査

- **問題**: `X-Bet365-*` (bet365)、`X-toto-*` (スポーツくじ toto)、`X-VeraJohn-*` (ベラジョン)、`X-WilliamHill-*`/`X-Flutter-*`/`X-Entain-*`/`X-Caesars-*`/`X-MGM-*`/`X-Wynn-*`/`X-Sands-*`/`X-PokerStars-*`/`X-DraftKings-*`/`X-FanDuel-*`/`X-888-*`/`X-Betfair-*`/`X-Betfred-*`/`X-Unibet-*`/`X-Bwin-*`/`X-Betway-*`/`X-Sportsbet-*`/`X-Pinnacle-*`/`X-Bodog-*`/`X-SBOBET-*`/`X-1xBet-*`/`X-Stake-*`/`X-Roobet-*`/`X-Casitabi-*`/`X-Bons-*`/`X-BIG-*`/`X-QueenCasino-*`/`X-LapinBet-*` は賭機の通知記録 — 送信側が書くことは自称。当選・出金通知偽装は賭博詐欺の典型。(`X-JRA-*`/`X-Boatrace-*` 等の公営競技は D536 で検出済み)
- **修正**: `Envelope` に `gambling_marks` + `has_gambling_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 賭印の自署を問え。

### Security — D548: `X-SECOM-*`/`X-ALSOK-*`/`X-Sakai-*` 等の警備・清掃・施設管理・引越・ストレージ印自称が未検査

- **問題**: `X-SECOM-*` (SECOM)、`X-ALSOK-*` (ALSOK)、`X-Sakai-*` (サカイ引越センター)、`X-G4S-*`/`X-Securitas-*`/`X-Prosegur-*`/`X-Brinks-*`/`X-AlliedUniversal-*`/`X-ZenNikkei-*`/`X-Rentokil-*`/`X-Orkin-*`/`X-Terminix-*`/`X-Duskin-*`/`X-Cintas-*`/`X-Aramark-*`/`X-Sodexo-*`/`X-CompassGroup-*`/`X-ISS-*`/`X-AeonDelight-*`/`X-UHaul-*`/`X-Art0073-*`/`X-PublicStorage-*`/`X-ExtraSpace-*`/`X-CubeSmart-*`/`X-Quraz-*`/`X-StorageKing-*` は施機の通知記録 — 送信側が書くことは自称。見積・契約更新偽装は施設詐欺の典型。
- **修正**: `Envelope` に `facility_marks` + `has_facility_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 施印の自署を問え。


### Security — D543: `X-Shell-*`/`X-ENEOS-*`/`X-SaudiAramco-*` 等の石油・鉱業・エネルギー資源印自称が未検査

- **問題**: `X-Shell-*` (Shell)、`X-ENEOS-*` (ENEOS)、`X-SaudiAramco-*` (Saudi Aramco)、`X-BP-*`/`X-Exxon-*`/`X-Chevron-*`/`X-TotalEnergies-*`/`X-Eni-*`/`X-Repsol-*`/`X-Equinor-*`/`X-ConocoPhillips-*`/`X-Petronas-*`/`X-ADNOC-*`/`X-QatarEnergy-*`/`X-Texaco-*`/`X-Mobil-*`/`X-Esso-*`/`X-Idemitsu-*`/`X-JERA-*`/`X-Schlumberger-*`/`X-Halliburton-*`/`X-BakerHughes-*`/`X-Vitol-*`/`X-Trafigura-*`/`X-Glencore-*`/`X-BHP-*`/`X-RioTinto-*`/`X-Vale-*`/`X-AngloAmerican-*`/`X-Freeport-*`/`X-JX-*`/`X-SumitomoMetal-*`/`X-MarubeniEnergy-*` は資機の通知記録 — 送信側が書くことは自称。燃料カード・請求書偽装は資源業界 BEC の典型。(`X-PGE-*`/`X-TEPCO-*`/`X-TokyoGas-*` 等の電気・ガス料金機は D520 で検出済み)
- **修正**: `Envelope` に `energy_marks` + `has_energy_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 資印の自署を問え。

### Security — D544: `X-Medtronic-*`/`X-Terumo-*`/`X-Sysmex-*` 等の医療機器・ライフサイエンス印自称が未検査

- **問題**: `X-Medtronic-*` (Medtronic)、`X-Terumo-*` (テルモ)、`X-Sysmex-*` (シスメックス)、`X-SiemensHealthineers-*`/`X-GEHealthcare-*`/`X-PhilipsHealthcare-*`/`X-Abbott-*`/`X-BostonScientific-*`/`X-Stryker-*`/`X-BD-*`/`X-Baxter-*`/`X-Fresenius-*`/`X-NihonKohden-*`/`X-Shimadzu-*`/`X-CanonMedical-*`/`X-FujifilmHealthcare-*`/`X-Hoya-*`/`X-Pentax-*`/`X-KarlStorz-*`/`X-ZimmerBiomet-*`/`X-SmithNephew-*`/`X-Cook-*`/`X-Edwards-*`/`X-Intuitive-*`/`X-Dexcom-*`/`X-ResMed-*`/`X-Varian-*`/`X-Elekta-*`/`X-Bruker-*`/`X-PerkinElmer-*`/`X-ThermoFisher-*`/`X-Agilent-*`/`X-Waters-*`/`X-Danaher-*`/`X-OlympusMedical-*` は医機の通知記録 — 送信側が書くことは自称。機器リコール・検査結果通知偽装は医療詐欺の典型。(`X-Bayer-*` 等の製薬は D542 で検出済み)
- **修正**: `Envelope` に `medtech_marks` + `has_medtech_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 医印の自署を問え。

### Security — D545: `X-Maersk-*`/`X-NYK-*`/`X-DBSchenker-*` 等の海運・貨物鉄道・フォワーダ印自称が未検査

- **問題**: `X-Maersk-*` (Maersk)、`X-NYK-*` (日本郵船)、`X-DBSchenker-*` (DB Schenker)、`X-MSC-*`/`X-CMACGM-*`/`X-COSCO-*`/`X-HapagLloyd-*`/`X-Evergreen-*`/`X-OOCL-*`/`X-YangMing-*`/`X-Zim-*`/`X-HMM-*`/`X-WanHai-*`/`X-PIL-*`/`X-Swire-*`/`X-MOL-*`/`X-KLine-*`/`X-UnionPacific-*`/`X-BNSF-*`/`X-CSX-*`/`X-NorfolkSouthern-*`/`X-CN-*`/`X-CPKCS-*`/`X-KuehneNagel-*`/`X-DSV-*`/`X-CEVA-*`/`X-Expeditors-*`/`X-CHRobinson-*`/`X-Panalpina-*`/`X-Dachser-*`/`X-Geodis-*`/`X-Hellmann-*`/`X-Seino-*`/`X-Fukuyama-*`/`X-Tonami-*`/`X-Meitetsu-*`/`X-SBS-*` は貨機の通知記録 — 送信側が書くことは自称。B/L・港湾費請求偽装は貿易詐欺の典型。(`X-FedEx-*`/`X-DHL-*`/`X-UPS-*`/`X-JapanPost-*`/`X-Sagawa-*`/`X-NX-*` 等の宅配・速達機は D475 で検出済み)
- **修正**: `Envelope` に `freight_marks` + `has_freight_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 貨印の自署を問え。


### Security — D540: `X-Boeing-*`/`X-SpaceX-*`/`X-JAXA-*` 等の航空宇宙・防衛印自称が未検査

- **問題**: `X-Boeing-*` (Boeing)、`X-SpaceX-*` (SpaceX)、`X-JAXA-*` (JAXA)、`X-Airbus-*`/`X-Lockheed-*`/`X-Raytheon-*`/`X-Northrop-*`/`X-BAE-*`/`X-GeneralDynamics-*`/`X-L3Harris-*`/`X-Embraer-*`/`X-Bombardier-*`/`X-MitsubishiHeavy-*`/`X-KawasakiHeavy-*`/`X-GEAviation-*`/`X-PrattWhitney-*`/`X-Safran-*`/`X-Leonardo-*`/`X-Thales-*`/`X-Dassault-*`/`X-BlueOrigin-*`/`X-RocketLab-*`/`X-ULA-*`/`X-NASA-*`/`X-Ball-*`/`X-Maxar-*`/`X-AerojetRocketdyne-*`/`X-SierraSpace-*`/`X-FireflyAerospace-*`/`X-RelativitySpace-*`/`X-Arianespace-*` は航機の通知記録 — 送信側が書くことは自称。受注・保守通知偽装は防衛産業 BEC の典型。(`X-IHI-*`/`X-Kawasaki-*` は D538、`X-Garmin-*` は D530 で検出済み)
- **修正**: `Envelope` に `aerospace_marks` + `has_aerospace_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 航印の自署を問え。

### Security — D541: `X-TomTom-*`/`X-Navitime-*`/`X-Pioneer-*` 等の地図・ナビ・カーオーディオ・ホームオーディオ印自称が未検査

- **問題**: `X-TomTom-*` (TomTom)、`X-Navitime-*` (NAVITIME)、`X-Pioneer-*` (Pioneer)、`X-HERE-*`/`X-Mapbox-*`/`X-GoogleMaps-*`/`X-OpenStreetMap-*`/`X-MapQuest-*`/`X-BingMaps-*`/`X-Zenrin-*`/`X-Mapion-*`/`X-MapFan-*`/`X-Alpine-*`/`X-Kenwood-*`/`X-Clarion-*`/`X-JVC-*`/`X-Carrozzeria-*`/`X-Kicker-*`/`X-JLAudio-*`/`X-Focal-*`/`X-Audison-*`/`X-RockfordFosgate-*`/`X-MTX-*`/`X-HarmanKardon-*`/`X-JBL-*`/`X-Bose-*`/`X-Sonos-*`/`X-Denon-*`/`X-Marantz-*`/`X-Onkyo-*`/`X-TEAC-*` は図機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `navigation_marks` + `has_navigation_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 図印の自署を問え。

### Security — D542: `X-Pfizer-*`/`X-Takeda-*`/`X-Eisai-*` 等の製薬・バイオ印自称が未検査

- **問題**: `X-Pfizer-*` (Pfizer)、`X-Takeda-*` (武田)、`X-Eisai-*` (エーザイ)、`X-Moderna-*`/`X-Novartis-*`/`X-Roche-*`/`X-AstraZeneca-*`/`X-GSK-*`/`X-Merck-*`/`X-EliLilly-*`/`X-Bayer-*`/`X-Sanofi-*`/`X-JNJ-*`/`X-BMS-*`/`X-Astellas-*`/`X-DaiichiSankyo-*`/`X-Otsuka-*`/`X-Chugai-*`/`X-Shionogi-*`/`X-Ono-*`/`X-KyowaKirin-*`/`X-MeijiSeika-*`/`X-Taisho-*`/`X-Hisamitsu-*`/`X-Teijin-*`/`X-AbbVie-*`/`X-Amgen-*`/`X-Gilead-*`/`X-Biogen-*`/`X-Regeneron-*`/`X-Vertex-*`/`X-CSL-*`/`X-Novo-*`/`X-BoehringerIngelheim-*` は製薬機の通知記録 — 送信側が書くことは自称。治験・処方通知偽装は医療詐欺の典型。
- **修正**: `Envelope` に `pharma_marks` + `has_pharma_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 薬印の自署を問え。


### Security — D537: `X-Intel-*`/`X-NVIDIA-*`/`X-TSMC-*` 等の半導体・ストレージ印自称が未検査

- **問題**: `X-Intel-*` (Intel)、`X-NVIDIA-*` (NVIDIA)、`X-TSMC-*` (TSMC)、`X-AMD-*`/`X-Qualcomm-*`/`X-Broadcom-*`/`X-Micron-*`/`X-TI-*`/`X-ST-*`/`X-NXP-*`/`X-Infineon-*`/`X-Renesas-*`/`X-Analog-*`/`X-Marvell-*`/`X-ARM-*`/`X-GlobalFoundries-*`/`X-UMC-*`/`X-SMIC-*`/`X-MediaTek-*`/`X-Skyworks-*`/`X-Qorvo-*`/`X-Realtek-*`/`X-Winbond-*`/`X-Cypress-*`/`X-Microchip-*`/`X-onsemi-*`/`X-ROHM-*`/`X-Kioxia-*`/`X-WesternDigital-*`/`X-Seagate-*`/`X-SanDisk-*`/`X-Kingston-*`/`X-ADATA-*`/`X-Transcend-*`/`X-Crucial-*`/`X-SKHynix-*`/`X-Solidigm-*` は半導体機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `semiconductor_marks` + `has_semiconductor_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 半導体印の自署を問え。

### Security — D538: `X-Siemens-*`/`X-Fanuc-*`/`X-Komatsu-*` 等の産業機械・重工・建機印自称が未検査

- **問題**: `X-Siemens-*` (Siemens)、`X-Fanuc-*` (FANUC)、`X-Komatsu-*` (コマツ)、`X-ABB-*`/`X-Schneider-*`/`X-Honeywell-*`/`X-Emerson-*`/`X-Rockwell-*`/`X-Yokogawa-*`/`X-Omron-*`/`X-Keyence-*`/`X-MitsubishiElectric-*`/`X-Okuma-*`/`X-Makino-*`/`X-DMGMori-*`/`X-Amada-*`/`X-Kubota-*`/`X-Caterpillar-*`/`X-JohnDeere-*`/`X-JCB-*`/`X-SANY-*`/`X-XCMG-*`/`X-Zoomlion-*`/`X-Doosan-*`/`X-Tadano-*`/`X-Kobelco-*`/`X-Sumitomo-*`/`X-IHI-*`/`X-Kawasaki-*`/`X-JFE-*`/`X-NipponSteel-*`/`X-POSCO-*` は産業機の通知記録 — 送信側が書くことは自称。部品発注・納期通知偽装は製造業 BEC の典型。(`X-Hitachi-*`/`X-Toshiba-*` は D496 で検出済み)
- **修正**: `Envelope` に `industrial_marks` + `has_industrial_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 産業印の自署を問え。

### Security — D539: `X-Dell-*`/`X-Xerox-*`/`X-KonicaMinolta-*` 等の PC・オフィス機器・印刷・計測印自称が未検査

- **問題**: `X-Dell-*` (Dell)、`X-Xerox-*` (Xerox)、`X-KonicaMinolta-*` (コニカミノルタ)、`X-HP-*`/`X-Lenovo-*`/`X-Acer-*`/`X-ASUS-*`/`X-MSI-*`/`X-Gigabyte-*`/`X-AOC-*`/`X-BenQ-*`/`X-ViewSonic-*`/`X-LG-*`/`X-RicohImaging-*`/`X-Lexmark-*`/`X-OKI-*`/`X-UTAX-*`/`X-ToshibaTEC-*`/`X-Mutoh-*`/`X-RolandDG-*`/`X-Graphtec-*`/`X-Mimaki-*`/`X-Zebra-*`/`X-Cognex-*`/`X-FaroArm-*`/`X-HexagonMI-*`/`X-KeyenceMI-*` は事務機の通知記録 — 送信側が書くことは自称。トナー・保守契約詐欺の典型印。(`X-Ricoh-*`/`X-Sharp-*`/`X-Canon-*`/`X-EPSON-*`/`X-Brother-*`/`X-Kyocera-*`/`X-Fujitsu-*`/`X-NEC-*`/`X-Toshiba-*`/`X-Panasonic-*`/`X-Sony-*` は D496 で検出済み)
- **修正**: `Envelope` に `office_marks` + `has_office_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 事務印の自署を問え。


### Security — D534: `X-Ticketmaster-*`/`X-Eplus-*`/`X-LawsonTicket-*` 等のチケット販売・プレイガイド印自称が未検査

- **問題**: `X-Ticketmaster-*` (Ticketmaster)、`X-Eplus-*` (イープラス)、`X-LawsonTicket-*` (ローチケ)、`X-LiveNation-*`/`X-StubHub-*`/`X-Viagogo-*`/`X-SeatGeek-*`/`X-TicketWeb-*`/`X-CNPlayGuide-*`/`X-RakutenTicket-*`/`X-AXS-*`/`X-SeeTickets-*`/`X-TicketOne-*`/`X-Ticketek-*`/`X-Ticketcorner-*`/`X-Eventim-*`/`X-Dice-*`/`X-GigsAndTours-*`/`X-Skiddle-*`/`X-TicketSellers-*`/`X-Gigsberg-*`/`X-TickPick-*`/`X-VividSeats-*`/`X-TicketCity-*`/`X-TicketNetwork-*`/`X-HelloTickets-*`/`X-TicketSwap-*`/`X-Tixr-*`/`X-ShowClix-*`/`X-SeeTix-*`/`X-TicketFairy-*`/`X-CrowdTix-*` は券機の通知記録 — 送信側が書くことは自称。当選・リセール詐欺の典型印。(`X-Eventbrite-*`/`X-Meetup-*` は D459、`X-Pia-*` は先行で検出済み)
- **修正**: `Envelope` に `ticket_marks` + `has_ticket_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 券印の自署を問え。

### Security — D535: `X-Marriott-*`/`X-Hilton-*`/`X-ToyokoInn-*` 等のホテル・宿泊予約印自称が未検査

- **問題**: `X-Marriott-*` (Marriott)、`X-Hilton-*` (Hilton)、`X-ToyokoInn-*` (東横イン)、`X-Hyatt-*`/`X-IHG-*`/`X-Accor-*`/`X-Sheraton-*`/`X-Westin-*`/`X-RitzCarlton-*`/`X-FourSeasons-*`/`X-MandarinOriental-*`/`X-Peninsula-*`/`X-ShangriLa-*`/`X-InterContinental-*`/`X-HolidayInn-*`/`X-BestWestern-*`/`X-ChoiceHotels-*`/`X-Wyndham-*`/`X-Radisson-*`/`X-PremierInn-*`/`X-Travelodge-*`/`X-TokyuHotel-*`/`X-PrinceHotel-*`/`X-APAHotel-*`/`X-RouteInn-*`/`X-SuperHotel-*`/`X-DormyInn-*`/`X-ComfortInn-*`/`X-Jalan-*`/`X-RakutenTravel-*`/`X-Rurubu-*`/`X-TripAdvisor-*`/`X-CapsuleHotel-*`/`X-NineHours-*` は宿機の通知記録 — 送信側が書くことは自称。予約キャンセル・ポイント失効詐欺の典型印。(`X-Expedia-*`/`X-Hotels-*`/`X-Airbnb-*`/`X-Booking-*`/`X-Agoda-*`/`X-Kayak-*` は D468 で検出済み)
- **修正**: `Envelope` に `hotel_marks` + `has_hotel_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 宿印の自署を問え。

### Security — D536: `X-Disney-*`/`X-USJ-*`/`X-JRA-*` 等のテーマパーク・公営競技・映画館・カラオケ・温浴印自称が未検査

- **問題**: `X-Disney-*` (Disney)、`X-USJ-*` (USJ)、`X-JRA-*` (JRA)、`X-UniversalStudios-*`/`X-Legoland-*`/`X-Fujikyu-*`/`X-Toshimaen-*`/`X-Nagashima-*`/`X-BoatRace-*`/`X-Keirin-*`/`X-AutoRace-*`/`X-Pachinko-*`/`X-Dynam-*`/`X-Marukan-*`/`X-Nirasaki-*`/`X-TOHO-*`/`X-AeonCinema-*`/`X-109Cinemas-*`/`X-Shochiku-*`/`X-MOVIX-*`/`X-BigEcho-*`/`X-Shidax-*`/`X-JoySound-*`/`X-DAM-*`/`X-Round1-*`/`X-Gokurakuyu-*`/`X-RaikuSpa-*`/`X-Spadium-*`/`X-Ofuro-*`/`X-Tenpoyu-*`/`X-KenkoLand-*`/`X-Minatomachi-*` は娯楽機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `leisure_marks` + `has_leisure_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 娯楽印の自署を問え。


### Security — D531: `X-Shiseido-*`/`X-DHC-*`/`X-Amway-*` 等の化粧品・スキンケア・MLM 美容印自称が未検査

- **問題**: `X-Shiseido-*` (資生堂)、`X-DHC-*` (DHC)、`X-Amway-*` (Amway)、`X-Kose-*`/`X-Pola-*`/`X-Fancl-*`/`X-Orbis-*`/`X-EsteeLauder-*`/`X-Lancome-*`/`X-Kiehls-*`/`X-Clinique-*`/`X-Revlon-*`/`X-MaryKay-*`/`X-Avon-*`/`X-NuSkin-*`/`X-Herbalife-*`/`X-Tupperware-*`/`X-MAC-*`/`X-NARS-*`/`X-ShuUemura-*`/`X-THREE-*`/`X-RMK-*`/`X-SUQQU-*`/`X-CPB-*`/`X-Decorte-*`/`X-Albion-*`/`X-Covermark-*`/`X-Kanebo-*`/`X-Sofina-*`/`X-Biore-*`/`X-Curel-*`/`X-Freeplus-*`/`X-Minon-*`/`X-HadaLabo-*`/`X-MelanoCC-*`/`X-ROHTO-*`/`X-Sante-*`/`X-Garnier-*`/`X-LOreal-*`/`X-Nivea-*`/`X-Neutrogena-*`/`X-CeraVe-*`/`X-Aveeno-*`/`X-Vaseline-*` は美機の通知記録 — 送信側が書くことは自称。無料モニター・サンプル詐欺の典型印。
- **修正**: `Envelope` に `beauty_marks` + `has_beauty_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 美印の自署を問え。

### Security — D532: `X-Kumon-*`/`X-Benesse-*`/`X-Shinkenzemi-*` 等の塾・語学・子供教育印自称が未検査

- **問題**: `X-Kumon-*` (くもん)、`X-Benesse-*` (ベネッセ)、`X-Shinkenzemi-*` (進研ゼミ)、`X-Zkai-*`/`X-Toshin-*`/`X-Sundai-*`/`X-Kawaijuku-*`/`X-Meiko-*`/`X-Nichii-*`/`X-Gaba-*`/`X-AeonECC-*`/`X-ECC-*`/`X-NovaKids-*`/`X-Berlitz-*`/`X-Rosetta-*`/`X-Babbel-*`/`X-iTalki-*`/`X-Preply-*`/`X-Cambly-*`/`X-VIPKid-*`/`X-RareJob-*`/`X-NativeCamp-*`/`X-DMMeikaiwa-*`/`X-Prodigy-*`/`X-TypingClub-*`/`X-IXL-*`/`X-Khan-*`/`X-Sumdog-*`/`X-Smartick-*`/`X-EdClub-*`/`X-RazKids-*`/`X-ReadingEggs-*` は学習機の通知記録 — 送信側が書くことは自称。(`X-Duolingo-*`/`X-KhanAcademy-*` は D477 で検出済み)
- **修正**: `Envelope` に `cram_marks` + `has_cram_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 学習印の自署を問え。

### Security — D533: `X-Daiso-*`/`X-PG-*`/`X-Chewy-*` 等の日用品・消費財・100 円ショップ・ペット用品印自称が未検査

- **問題**: `X-Daiso-*` (ダイソー)、`X-PG-*` (P&G)、`X-Chewy-*` (Chewy)、`X-Unilever-*`/`X-ColgatePalmolive-*`/`X-KimberlyClark-*`/`X-Reckitt-*`/`X-Henkel-*`/`X-Kao-*`/`X-Lion-*`/`X-Johnson-*`/`X-ScotchBrite-*`/`X-3M-*`/`X-Kobayashi-*`/`X-Earth-*`/`X-Estee-*`/`X-Seria-*`/`X-CanDo-*`/`X-Watts-*`/`X-3Coins-*`/`X-NaturalKitchen-*`/`X-FlyingTiger-*`/`X-PetSmart-*`/`X-Petco-*`/`X-Zooplus-*`/`X-Fressnapf-*`/`X-PetValu-*`/`X-AeonPet-*`/`X-KojimaPet-*`/`X-CainzPet-*` は日用品機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `fmcg_marks` + `has_fmcg_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 日用品印の自署を問え。


### Security — D528: `X-McDonalds-*`/`X-Starbucks-*`/`X-Sushiro-*` 等のファストフード・飲食チェーン印自称が未検査

- **問題**: `X-McDonalds-*` (マクドナルド)、`X-Starbucks-*` (Starbucks)、`X-Dominos-*`/`X-KFC-*`/`X-Subway-*`/`X-BurgerKing-*`/`X-PizzaHut-*`/`X-Wendys-*`/`X-Chipotle-*`/`X-TacoBell-*`/`X-Dunkin-*`/`X-TimHortons-*`/`X-ChickFilA-*`/`X-PandaExpress-*`/`X-MosBurger-*`/`X-Sukiya-*`/`X-Yoshinoya-*`/`X-Matsuya-*`/`X-Saizeriya-*`/`X-Dennys-*`/`X-KuraSushi-*`/`X-Sushiro-*`/`X-HamaSushi-*`/`X-KappaSushi-*`/`X-Torikizoku-*`/`X-Skylark-*`/`X-Cocos-*`/`X-Jonathans-*`/`X-Bamiyan-*`/`X-RoyalHost-*`/`X-OliveGarden-*`/`X-CrackerBarrel-*`/`X-CheesecakeFactory-*`/`X-Nandos-*`/`X-Wagamama-*`/`X-Zizzi-*`/`X-Wetherspoons-*`/`X-Greggs-*`/`X-PretAManger-*` は食機の通知記録 — 送信側が書くことは自称。食事券・クーポン詐欺の典型印。(`X-Gusto-*` は D466 で検出済み)
- **修正**: `Envelope` に `restaurant_marks` + `has_restaurant_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 食印の自署を問え。

### Security — D529: `X-Nike-*`/`X-Adidas-*`/`X-Decathlon-*`/`X-Montbell-*` 等のスポーツ・アウトドアブランド印自称が未検査

- **問題**: `X-Nike-*` (Nike)、`X-Adidas-*` (adidas)、`X-Decathlon-*` (Decathlon)、`X-Montbell-*` (mont-bell)、`X-Puma-*`/`X-UnderArmour-*`/`X-NewBalance-*`/`X-ASICS-*`/`X-Mizuno-*`/`X-OnRunning-*`/`X-HOKA-*`/`X-Salomon-*`/`X-TheNorthFace-*`/`X-Patagonia-*`/`X-Columbia-*`/`X-Arcteryx-*`/`X-REI-*`/`X-BassPro-*`/`X-Cabelas-*`/`X-Dicks-*`/`X-Fanatics-*`/`X-Xebio-*`/`X-Himaraya-*`/`X-Alpen-*`/`X-Wilson-*`/`X-Yonex-*`/`X-Babolat-*`/`X-Callaway-*`/`X-TaylorMade-*`/`X-Ping-*`/`X-Titleist-*`/`X-Fila-*`/`X-Lotto-*`/`X-Umbro-*`/`X-Diadora-*` は武具機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `sports_marks` + `has_sports_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 武具印の自署を問え。

### Security — D530: `X-Fitbit-*`/`X-Garmin-*`/`X-Peloton-*`/`X-GoldGym-*` 等のフィットネス・ウェアラブル・ジム印自称が未検査

- **問題**: `X-Fitbit-*` (Fitbit)、`X-Garmin-*` (Garmin)、`X-Peloton-*` (Peloton)、`X-GoldGym-*` (ゴールドジム)、`X-Polar-*`/`X-Suunto-*`/`X-Coros-*`/`X-Whoop-*`/`X-Oura-*`/`X-Strava-*`/`X-Zwift-*`/`X-MyFitnessPal-*`/`X-Noom-*`/`X-Freeletics-*`/`X-Runkeeper-*`/`X-MapMyRun-*`/`X-Komoot-*`/`X-AllTrails-*`/`X-Calm-*`/`X-Headspace-*`/`X-BetterSleep-*`/`X-Bodybuilding-*`/`X-NikeTraining-*`/`X-AdidasRunning-*`/`X-Fiit-*`/`X-Anytime-*`/`X-Tipness-*`/`X-Renaissance-*`/`X-KonamiSports-*`/`X-CentralSports-*`/`X-Major4-*`/`X-LAVA-*`/`X-Curves-*` は健機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `fitness_marks` + `has_fitness_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 健印の自署を問え。


### Security — D525: `X-Kroger-*`/`X-Tesco-*`/`X-AEON-*`/`X-Lawson-*`/`X-Uniqlo-*`/`X-Yodobashi-*` 等の食料品・日用品・コンビニ・家電・アパレル・百貨店印自称が未検査

- **問題**: `X-Kroger-*` (Kroger)、`X-Tesco-*` (Tesco)、`X-AEON-*` (イオン)、`X-Sainsbury-*`/`X-ASDA-*`/`X-Morrisons-*`/`X-Aldi-*`/`X-Lidl-*`/`X-SevenI-*`/`X-FamilyMart-*`/`X-Lawson-*`/`X-Ministop-*`/`X-Woolworths-*`/`X-Coles-*`/`X-Safeway-*`/`X-Publix-*`/`X-Wegmans-*`/`X-TraderJoes-*`/`X-WholeFoods-*`/`X-Sprouts-*`/`X-Yamada-*`/`X-BicCamera-*`/`X-Yodobashi-*`/`X-Joshin-*`/`X-Kojima-*`/`X-Edion-*`/`X-MediaMarkt-*`/`X-Saturn-*`/`X-Elkjop-*`/`X-Gigantti-*`/`X-Uniqlo-*`/`X-GU-*`/`X-Shimamura-*`/`X-Workman-*`/`X-AOKI-*`/`X-Aoyama-*`/`X-Macys-*`/`X-Nordstrom-*`/`X-Bloomingdales-*`/`X-Kohls-*`/`X-JCPenney-*`/`X-Dillards-*` は商機の通知記録 — 送信側が書くことは自称。ポイント・クーポン詐欺の典型印。(`X-Walmart-*` は D494 で検出済み)
- **修正**: `Envelope` に `grocery_marks` + `has_grocery_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 商印の自署を問え。

### Security — D526: `X-IKEA-*`/`X-Wayfair-*`/`X-Nitori-*`/`X-Muji-*`/`X-HomeDepot-*`/`X-Bunnings-*` 等の家具・ホームセンター・インテリア印自称が未検査

- **問題**: `X-IKEA-*` (IKEA)、`X-Wayfair-*` (Wayfair)、`X-Nitori-*` (ニトリ)、`X-Houzz-*`/`X-PotteryBarn-*`/`X-WestElm-*`/`X-CrateBarrel-*`/`X-CB2-*`/`X-RH-*`/`X-HermanMiller-*`/`X-Steelcase-*`/`X-Vitra-*`/`X-Muji-*`/`X-Francfranc-*`/`X-Loft-*`/`X-TokyuHands-*`/`X-Donki-*`/`X-MegaDonki-*`/`X-Cainz-*`/`X-Komeri-*`/`X-DCM-*`/`X-HomeDepot-*`/`X-Lowes-*`/`X-Menards-*`/`X-AceHardware-*`/`X-TractorSupply-*`/`X-FloorDecor-*`/`X-BuildDotCom-*`/`X-Rona-*`/`X-RenoDepot-*`/`X-HomeHardware-*`/`X-Bunnings-*`/`X-Mitre10-*`/`X-Masters-*` は具機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `furniture_marks` + `has_furniture_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 具印の自署を問え。

### Security — D527: `X-Boots-*`/`X-Matsukiyo-*`/`X-Welcia-*`/`X-Sephora-*`/`X-Tsuruha-*`/`X-iHerb-*` 等のドラッグストア・調剤・化粧品印自称が未検査

- **問題**: `X-Boots-*` (Boots)、`X-Matsukiyo-*` (マツキヨ)、`X-Sephora-*` (Sephora)、`X-Welcia-*`/`X-SugiDrug-*`/`X-Tsuruha-*`/`X-Cosmos-*`/`X-Cocokara-*`/`X-Shoppers-*`/`X-Rexall-*`/`X-ChemistWarehouse-*`/`X-DuaneReade-*`/`X-RiteAid-*`/`X-Mannings-*`/`X-Watsons-*`/`X-Guardian-*`/`X-Sundrug-*`/`X-DaikokuDrug-*`/`X-Kirindo-*`/`X-Tomods-*`/`X-Ulta-*`/`X-LOccitane-*`/`X-TheBodyShop-*`/`X-Lush-*`/`X-BathBodyWorks-*`/`X-VictoriasSecret-*`/`X-iHerb-*`/`X-GNC-*`/`X-VitaminShoppe-*`/`X-HollandBarrett-*` は薬機の通知記録 — 送信側が書くことは自称。(`X-CVS-*`/`X-Walgreens-*` は D481 で検出済み)
- **修正**: `Envelope` に `drugstore_marks` + `has_drugstore_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 薬印の自署を問え。


### Security — D522: `X-JREast-*`/`X-Tokyu-*`/`X-Amtrak-*`/`X-DeutscheBahn-*`/`X-SNCF-*`/`X-Kintetsu-*` 等の鉄道・公共交通印自称が未検査

- **問題**: `X-JREast-*` (JR東日本)、`X-Tokyu-*` (東急)、`X-Amtrak-*` (Amtrak)、`X-JRWest-*`/`X-JRCentral-*`/`X-JRKyushu-*`/`X-JRHokkaido-*`/`X-Odakyu-*`/`X-Keikyu-*`/`X-Keio-*`/`X-Seibu-*`/`X-Tobu-*`/`X-Hankyu-*`/`X-Hanshin-*`/`X-Kintetsu-*`/`X-Nankai-*`/`X-Nishitetsu-*`/`X-TokyoMetro-*`/`X-DeutscheBahn-*`/`X-SNCF-*`/`X-Trenitalia-*`/`X-Eurostar-*`/`X-Thalys-*`/`X-NSInternational-*`/`X-SBB-*`/`X-Renfe-*`/`X-IRCTC-*`/`X-ViaRail-*`/`X-KMB-*`/`X-MTR-*`/`X-TOEI-*`/`X-OsakaMetro-*`/`X-KyotoSubway-*`/`X-YokohamaSubway-*`/`X-SapporoSubway-*`/`X-SendaiSubway-*`/`X-NagoyaSubway-*` は軌機の通知記録 — 送信側が書くことは自称。乗車券・ポイント詐欺の典型印。
- **修正**: `Envelope` に `rail_marks` + `has_rail_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 軌印の自署を問え。

### Security — D523: `X-Clio-*`/`X-LegalZoom-*`/`X-Westlaw-*`/`X-PACER-*`/`X-Relativity-*`/`X-Nuix-*` 等の法務・法曹実務印自称が未検査

- **問題**: `X-Clio-*` (Clio)、`X-LegalZoom-*` (LegalZoom)、`X-Westlaw-*` (Westlaw)、`X-RocketLawyer-*`/`X-PACER-*`/`X-CourtListener-*`/`X-ThomsonReuters-*`/`X-CaseText-*`/`X-LinkSquares-*`/`X-LegalServer-*`/`X-Filevine-*`/`X-MyCase-*`/`X-PracticePanther-*`/`X-Smokeball-*`/`X-CosmoLex-*`/`X-ZolaSuite-*`/`X-CareT-*`/`X-AbacusLaw-*`/`X-Actionstep-*`/`X-Centerbase-*`/`X-Litify-*`/`X-NeotaLogic-*`/`X-HotDocs-*`/`X-ContractPodAi-*`/`X-Relativity-*`/`X-Everlaw-*`/`X-Logikcull-*`/`X-Disco-*`/`X-Reveal-*`/`X-Exterro-*`/`X-Nuix-*` は法機の通知記録 — 送信側が書くことは自称。(`X-LexisNexis-*`/`X-Ironclad-*`/`X-Evisort-*`/`X-Juro-*`/`X-Icertis-*`/`X-Agiloft-*`/`X-Conga-*` は D478 で検出済み)
- **修正**: `Envelope` に `legal_marks` + `has_legal_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 法印の自署を問え。

### Security — D524: `X-Tinder-*`/`X-Bumble-*`/`X-Hinge-*`/`X-Pairs-*`/`X-Omiai-*`/`X-Match-*` 等の出会い系・マッチングアプリ印自称が未検査

- **問題**: `X-Tinder-*` (Tinder)、`X-Bumble-*` (Bumble)、`X-Pairs-*` (Pairs)、`X-Hinge-*`/`X-Match-*`/`X-OkCupid-*`/`X-Grindr-*`/`X-Omiai-*`/`X-Tapple-*`/`X-With-*`/`X-Happn-*`/`X-CoffeeMeetsBagel-*`/`X-Zoosk-*`/`X-eHarmony-*`/`X-Badoo-*`/`X-Tantan-*`/`X-Momo-*`/`X-Paktor-*`/`X-TheLeague-*`/`X-Raya-*`/`X-Feeld-*`/`X-HER-*`/`X-Thursday-*`/`X-Snack-*` は遇機の通知記録 — 送信側が書くことは自称。ロマンス詐欺の典型印。
- **修正**: `Envelope` に `dating_marks` + `has_dating_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 遇印の自署を問え。


### Security — D519: `X-Geico-*`/`X-AXA-*`/`X-TokioMarine-*`/`X-StateFarm-*`/`X-MetLife-*`/`X-NipponLife-*` 等の保険会社印自称が未検査

- **問題**: `X-Geico-*` (GEICO)、`X-AXA-*` (AXA)、`X-TokioMarine-*` (東京海上)、`X-StateFarm-*`/`X-Progressive-*`/`X-Allstate-*`/`X-Allianz-*`/`X-Zurich-*`/`X-AIG-*`/`X-MetLife-*`/`X-Prudential-*`/`X-Aflac-*`/`X-LibertyMutual-*`/`X-Travelers-*`/`X-Nationwide-*`/`X-Chubb-*`/`X-Sompo-*`/`X-MSAD-*`/`X-DaiichiLife-*`/`X-NipponLife-*`/`X-MeijiYasuda-*`/`X-T&D-*`/`X-Manulife-*`/`X-SunLife-*`/`X-Aviva-*`/`X-Generali-*`/`X-Lemonade-*`/`X-OscarHealth-*`/`X-Academy-*`/`X-Everest-*`/`X-ArchCapital-*`/`X-RenaissanceRe-*`/`X-Hanover-*`/`X-CNA-*`/`X-Markel-*`/`X-Beazley-*`/`X-Hiscox-*`/`X-TokioKiln-*` は保機の通知記録 — 送信側が書くことは自称。保険金・解約返戻金詐欺の典型印。
- **修正**: `Envelope` に `insurance_marks` + `has_insurance_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 保印の自署を問え。

### Security — D520: `X-PGE-*`/`X-TEPCO-*`/`X-TokyoGas-*`/`X-EDF-*`/`X-DukeEnergy-*`/`X-NationalGrid-*` 等の公益事業印自称が未検査

- **問題**: `X-PGE-*` (PG&E)、`X-TEPCO-*` (東京電力)、`X-TokyoGas-*` (東京ガス)、`X-ConEd-*`/`X-DukeEnergy-*`/`X-Dominion-*`/`X-NationalGrid-*`/`X-EON-*`/`X-EDF-*`/`X-Enel-*`/`X-Iberdrola-*`/`X-Kanden-*`/`X-ChubuElectric-*`/`X-OsakaGas-*`/`X-Veolia-*`/`X-Suez-*`/`X-SouthernCompany-*`/`X-Exelon-*`/`X-NextEra-*`/`X-Ameren-*`/`X-XcelEnergy-*`/`X-PSEG-*`/`X-HokkaidoElectric-*`/`X-TohokuElectric-*`/`X-HokurikuElectric-*`/`X-ChugokuElectric-*`/`X-ShikokuElectric-*`/`X-KyushuElectric-*`/`X-OkinawaElectric-*`/`X-SaibuGas-*`/`X-HiroshimaGas-*` は灯機の通知記録 — 送信側が書くことは自称。料金未払い停止詐欺の典型印。(水道会社の一部は D518 で検出済み)
- **修正**: `Envelope` に `utility_marks` + `has_utility_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 灯印の自署を問え。

### Security — D521: `X-Toyota-*`/`X-Honda-*`/`X-Hertz-*`/`X-Tesla-*`/`X-BMW-*`/`X-Ford-*` 等の自動車メーカー・レンタカー・カーシェア印自称が未検査

- **問題**: `X-Toyota-*` (Toyota)、`X-Honda-*` (Honda)、`X-Hertz-*` (Hertz)、`X-Avis-*`/`X-Enterprise-*`/`X-Turo-*`/`X-Getaround-*`/`X-TimesCar-*`/`X-OrixRental-*`/`X-ToyotaRental-*`/`X-NissanRental-*`/`X-Nissan-*`/`X-Ford-*`/`X-GM-*`/`X-Volkswagen-*`/`X-BMW-*`/`X-Mercedes-*`/`X-Audi-*`/`X-Porsche-*`/`X-Hyundai-*`/`X-Kia-*`/`X-Volvo-*`/`X-Tesla-*`/`X-Subaru-*`/`X-Mazda-*`/`X-MitsubishiMotors-*`/`X-Suzuki-*`/`X-Daihatsu-*`/`X-Lexus-*`/`X-Rivian-*`/`X-BYD-*`/`X-Polaris-*`/`X-Isuzu-*`/`X-Hino-*`/`X-Fuso-*`/`X-UDTrucks-*`/`X-MINI-*`/`X-Jaguar-*`/`X-LandRover-*`/`X-VolvoCars-*`/`X-Stellantis-*` は車機の通知記録 — 送信側が書くことは自称。リコール・車検詐欺の典型印。(`X-Lucid-*` は Lucid 系として既カバー)
- **修正**: `Envelope` に `automotive_marks` + `has_automotive_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 車印の自署を問え。


### Security — D516: `X-Netflix-*`/`X-Hulu-*`/`X-DisneyPlus-*`/`X-PrimeVideo-*`/`X-DAZN-*`/`X-TVer-*` 等の動画配信・OTT 印自称が未検査

- **問題**: `X-Netflix-*` (Netflix)、`X-Hulu-*` (Hulu)、`X-DisneyPlus-*` (Disney+)、`X-HBOMax-*`/`X-Max-*`/`X-ParamountPlus-*`/`X-Peacock-*`/`X-PrimeVideo-*`/`X-DAZN-*`/`X-UNEXT-*`/`X-Abema-*`/`X-TVer-*`/`X-Crunchyroll-*`/`X-Funimation-*`/`X-Viki-*`/`X-iQiyi-*`/`X-WeTV-*`/`X-DiscoveryPlus-*`/`X-AppleTVPlus-*`/`X-Roku-*`/`X-SlingTV-*`/`X-FuboTV-*`/`X-PlutoTV-*`/`X-Tubi-*`/`X-RakutenTV-*`/`X-Lemino-*`/`X-Mubi-*`/`X-BritBox-*`/`X-ITVX-*`/`X-Channel4-*`/`X-My5-*`/`X-SBSOnDemand-*`/`X-Kayo-*`/`X-Stan-*`/`X-Binge-*`/`X-Foxtel-*` は映機の通知記録 — 送信側が書くことは自称。アカウント停止詐欺の典型印。(`X-Twitch-*`/`X-YouTube-*` は D459 で検出済み)
- **修正**: `Envelope` に `streaming_marks` + `has_streaming_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 映印の自署を問え。

### Security — D517: `X-1Password-*`/`X-Bitwarden-*`/`X-NordVPN-*`/`X-Mullvad-*`/`X-Backblaze-*`/`X-Veeam-*` 等のパスワード管理・VPN・バックアップ印自称が未検査

- **問題**: `X-1Password-*` (1Password)、`X-Bitwarden-*` (Bitwarden)、`X-NordVPN-*` (NordVPN)、`X-LastPass-*`/`X-Dashlane-*`/`X-Keeper-*`/`X-ExpressVPN-*`/`X-Mullvad-*`/`X-Surfshark-*`/`X-CyberGhost-*`/`X-Windscribe-*`/`X-TunnelBear-*`/`X-Tailscale-*`/`X-ZeroTier-*`/`X-CloudflareWARP-*`/`X-PIA-*`/`X-ProtonVPN-*`/`X-Backblaze-*`/`X-Carbonite-*`/`X-CrashPlan-*`/`X-Acronis-*`/`X-Veeam-*`/`X-iDrive-*`/`X-Duplicati-*`/`X-restic-*`/`X-Rclone-*`/`X-ArqBackup-*`/`X-Enpass-*`/`X-RoboForm-*`/`X-StickyPassword-*`/`X-LogMeOnce-*`/`X-Passbolt-*`/`X-Strongbox-*`/`X-SafeInCloud-*` は鑰機の通知記録 — 送信側が書くことは自称。マスターパスワード詐取の典型印。
- **修正**: `Envelope` に `consumer_security_marks` + `has_consumer_security_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 鑰印の自署を問え。

### Security — D518: `X-IRS-*`/`X-NTA-*`/`X-GovUK-*`/`X-SSA-*`/`X-HMRC-*`/`X-myGov-*` 等の政府・税務・公共機関印自称が未検査

- **問題**: `X-IRS-*` (IRS)、`X-NTA-*` (国税庁)、`X-GovUK-*` (GOV.UK)、`X-eLTAX-*`/`X-MyNaportal-*`/`X-GovDelivery-*`/`X-SSA-*`/`X-Medicare-*`/`X-HealthCareGov-*`/`X-DMV-*`/`X-TurboTax-*`/`X-HRBlock-*`/`X-TaxAct-*`/`X-FreeTaxUSA-*`/`X-eTax-*`/`X-Kokuzeicho-*`/`X-ePost-*`/`X-SydneyWater-*`/`X-Energex-*`/`X-OriginEnergy-*`/`X-AGL-*`/`X-WaterCorp-*`/`X-USAGov-*`/`X-GovInfo-*`/`X-Grants-*`/`X-FEMA-*`/`X-CBSA-*`/`X-CRA-*`/`X-HMRC-*`/`X-DWP-*`/`X-NHS-*`/`X-Centrelink-*`/`X-myGov-*`/`X-ATO-*`/`X-ServiceNSW-*`/`X-ICBC-*` は官機の通知記録 — 送信側が書くことは自称。還付金・給付金詐欺の典型印。
- **修正**: `Envelope` に `government_marks` + `has_government_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 官印の自署を問え。


### Security — D513: `X-ANA-*`/`X-JAL-*`/`X-United-*`/`X-Delta-*`/`X-Emirates-*`/`X-Qantas-*` 等の航空・マイレージ印自称が未検査

- **問題**: `X-ANA-*` (ANA)、`X-JAL-*` (JAL)、`X-United-*` (United)、`X-Delta-*`/`X-AmericanAir-*`/`X-Southwest-*`/`X-Emirates-*`/`X-QatarAirways-*`/`X-Lufthansa-*`/`X-BritishAirways-*`/`X-AirFrance-*`/`X-KLM-*`/`X-SingaporeAir-*`/`X-Cathay-*`/`X-Qantas-*`/`X-Jetstar-*`/`X-Peach-*`/`X-Spring-*`/`X-Ryanair-*`/`X-EasyJet-*`/`X-Norwegian-*`/`X-TurkishAirlines-*`/`X-AirCanada-*`/`X-AlaskaAir-*`/`X-Frontier-*`/`X-SpiritAirlines-*`/`X-ANA-Mileage-*`/`X-JAL-Mileage-*`/`X-Skymark-*`/`X-PeachAviation-*` は空機の通知記録 — 送信側が書くことは自称。航空予約・マイル偽装はフィッシングの典型手口。
- **修正**: `Envelope` に `airline_marks` + `has_airline_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 空印の自署を問え。

### Security — D514: `X-Chase-*`/`X-MUFG-*`/`X-SMBC-*`/`X-HSBC-*`/`X-WellsFargo-*`/`X-Barclays-*` 等の伝統銀行・証券印自称が未検査

- **問題**: `X-Chase-*` (Chase)、`X-MUFG-*` (三菱UFJ)、`X-SMBC-*` (SMBC)、`X-BankOfAmerica-*`/`X-WellsFargo-*`/`X-Citi-*`/`X-Barclays-*`/`X-HSBC-*`/`X-Mizuho-*`/`X-Resona-*`/`X-JPBank-*`/`X-SBI-*`/`X-GoldmanSachs-*`/`X-MorganStanley-*`/`X-DeutscheBank-*`/`X-CreditAgricole-*`/`X-BNP-*`/`X-SocieteGenerale-*`/`X-ING-*`/`X-Santander-*`/`X-BBVA-*`/`X-USBank-*`/`X-PNC-*`/`X-CapitalOne-*`/`X-TD-*`/`X-RBC-*`/`X-Scotiabank-*`/`X-NAB-*`/`X-CommBank-*`/`X-Westpac-*`/`X-ANZ-*`/`X-MitsubishiUFJ-*`/`X-SevenBank-*`/`X-RakutenBank-*`/`X-SonyBank-*`/`X-PayPayBank-*`/`X-AeonBank-*`/`X-AuJibun-*` は金機の通知記録 — 送信側が書くことは自称。銀行通知の偽装は BEC/フィッシングの第一標的。
- **修正**: `Envelope` に `bank_marks` + `has_bank_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 金印の自署を問え。

### Security — D515: `X-MongoDB-*`/`X-Redis-*`/`X-Snowflake-*`/`X-PlanetScale-*`/`X-Neon-*`/`X-Firebase-*` 等のデータベース・データウェアハウス印自称が未検査

- **問題**: `X-MongoDB-*` (MongoDB)、`X-Redis-*` (Redis)、`X-Snowflake-*` (Snowflake)、`X-PlanetScale-*`/`X-Neon-*`/`X-Turso-*`/`X-Fauna-*`/`X-CockroachDB-*`/`X-Cassandra-*`/`X-ScyllaDB-*`/`X-ClickHouse-*`/`X-Databricks-*`/`X-BigQuery-*`/`X-Redshift-*`/`X-MotherDuck-*`/`X-DuckDB-*`/`X-SQLite-*`/`X-CouchDB-*`/`X-Firebase-*`/`X-SurrealDB-*`/`X-EdgeDB-*`/`X-Tigris-*`/`X-Xata-*`/`X-Upstash-*`/`X-KeyDB-*`/`X-Dragonfly-*`/`X-Valkey-*`/`X-TiDB-*`/`X-Cockroach-*`/`X-InfluxData-*` は庫機の通知記録 — 送信側が書くことは自称。(`X-Supabase-*` は D509 で検出済み)
- **修正**: `Envelope` に `database_marks` + `has_database_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 庫印の自署を問え。


### Security — D510: `X-OpenAI-*`/`X-Anthropic-*`/`X-Cohere-*`/`X-HuggingFace-*`/`X-Mistral-*`/`X-Pinecone-*` 等の AI・LLM・音声合成・会話インテリジェンス印自称が未検査

- **問題**: `X-OpenAI-*` (OpenAI)、`X-Anthropic-*` (Anthropic)、`X-Cohere-*` (Cohere)、`X-HuggingFace-*`/`X-Replicate-*`/`X-TogetherAI-*`/`X-Mistral-*`/`X-Perplexity-*`/`X-Groq-*`/`X-DeepSeek-*`/`X-OpenRouter-*`/`X-LangChain-*`/`X-Pinecone-*`/`X-Weaviate-*`/`X-Qdrant-*`/`X-Milvus-*`/`X-Chroma-*`/`X-Ollama-*`/`X-ElevenLabs-*`/`X-Runway-*`/`X-StabilityAI-*`/`X-Midjourney-*`/`X-CharacterAI-*`/`X-Jasper-*`/`X-CopyAI-*`/`X-WriteSonic-*`/`X-Synthesia-*`/`X-HeyGen-*`/`X-Descript-*`/`X-OtterAI-*`/`X-Fireflies-*`/`X-Grain-*`/`X-ReadAI-*`/`X-Gong-*`/`X-Chorus-*`/`X-Clari-*`/`X-PeopleAI-*`/`X-vLLM-*`/`X-LlamaIndex-*`/`X-Haystack-*`/`X-SemanticKernel-*`/`X-AutoGen-*`/`X-CrewAI-*` は智機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `ai_marks` + `has_ai_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 智印の自署を問え。

### Security — D511: `X-Docomo-*`/`X-KDDI-*`/`X-SoftBank-*`/`X-Verizon-*`/`X-TMobile-*`/`X-Vodafone-*` 等の通信キャリア・MVNO 印自称が未検査

- **問題**: `X-Docomo-*` (docomo)、`X-KDDI-*` (KDDI)、`X-SoftBank-*` (SoftBank)、`X-AUOne-*`/`X-UQWiMAX-*`/`X-RakutenMobile-*`/`X-IIJmio-*`/`X-SoNet-*`/`X-JCOM-*`/`X-Plala-*`/`X-Verizon-*`/`X-ATT-*`/`X-TMobile-*`/`X-Sprint-*`/`X-Vodafone-*`/`X-O2-*`/`X-EE-*`/`X-Three-*`/`X-BT-*`/`X-SkyBroadband-*`/`X-Telstra-*`/`X-Optus-*`/`X-Rogers-*`/`X-Bell-*`/`X-Telus-*`/`X-Shaw-*`/`X-OrangeMobile-*`/`X-Movistar-*`/`X-Telefonica-*`/`X-Telenor-*`/`X-TeliaSonera-*`/`X-SwisscomMobile-*`/`X-TIM-*`/`X-WindTre-*`/`X-Bouygues-*`/`X-SFR-*`/`X-FreeMobile-*` は線機の通知記録 — 送信側が書くことは自称。(`X-OCN-*`/`X-BIGLOBE-*`/`X-nifty-*`/`X-dti-*` は D426 で検出済み)
- **修正**: `Envelope` に `telecom_marks` + `has_telecom_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 線印の自署を問え。

### Security — D512: `X-Chrome-*`/`X-Firefox-*`/`X-Brave-*`/`X-DuckDuckGo-*`/`X-Safari-*`/`X-Kagi-*` 等のブラウザ・検索エンジン印自称が未検査

- **問題**: `X-Chrome-*` (Chrome)、`X-Firefox-*` (Firefox)、`X-Brave-*` (Brave)、`X-Opera-*`/`X-Vivaldi-*`/`X-Safari-*`/`X-Edge-*`/`X-TorBrowser-*`/`X-Waterfox-*`/`X-LibreWolf-*`/`X-DuckDuckGo-*`/`X-Startpage-*`/`X-Ecosia-*`/`X-Qwant-*`/`X-Kagi-*`/`X-Neeva-*`/`X-Mojeek-*`/`X-BraveSearch-*`/`X-Iron-*`/`X-Midori-*`/`X-Falkon-*`/`X-Qutebrowser-*`/`X-NetSurf-*`/`X-Lynx-*`/`X-PaleMoon-*`/`X-SeaMonkey-*`/`X-Maxthon-*`/`X-UCBrowser-*`/`X-SamsungInternet-*`/`X-HuaweiBrowser-*`/`X-MiBrowser-*` は覧機の通知記録 — 送信側が書くことは自称。(`X-ARC-*` は D427、`X-Chrome-River-*` は D489 で検出済み)
- **修正**: `Envelope` に `browser_marks` + `has_browser_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 覧印の自署を問え。


### Security — D507: `X-Joplin-*`/`X-Logseq-*`/`X-HackMD-*`/`X-Typora-*`/`X-Anytype-*`/`X-RemNote-*` 等のノート・執筆・PKM 印自称が未検査

- **問題**: `X-Joplin-*` (Joplin)、`X-Logseq-*` (Logseq)、`X-HackMD-*` (HackMD)、`X-Foam-*`/`X-Dendron-*`/`X-Trilium-*`/`X-Simplenote-*`/`X-StandardNotes-*`/`X-Bear-*`/`X-Ulysses-*`/`X-iAWriter-*`/`X-Inkdrop-*`/`X-Zettlr-*`/`X-MarkText-*`/`X-Typora-*`/`X-BoostNote-*`/`X-HedgeDoc-*`/`X-CodiMD-*`/`X-Etherpad-*`/`X-CryptPad-*`/`X-SiYuan-*`/`X-Anytype-*`/`X-Capacities-*`/`X-Tana-*`/`X-RemNote-*`/`X-Amplenote-*`/`X-Notejoy-*`/`X-Notability-*`/`X-GoodNotes-*`/`X-Squid-*`/`X-Nebo-*`/`X-Flexcil-*`/`X-Scapple-*`/`X-Freeplane-*`/`X-FreeMind-*`/`X-TiddlyWiki-*`/`X-Mem-*`/`X-Supernotes-*`/`X-Quip-*`/`X-Paper-*`/`X-Slab-*`/`X-Slite-*`/`X-Nuclino-*`/`X-Outline-*`/`X-BookStack-*`/`X-DokuWiki-*`/`X-Craft-*` は筆記機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `notes_marks` + `has_notes_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 筆記印の自署を問え。

### Security — D508: `X-Excalidraw-*`/`X-Visio-*`/`X-MindMeister-*`/`X-tldraw-*`/`X-XMind-*`/`X-Padlet-*` 等の図解・ホワイトボード・マインドマップ印自称が未検査

- **問題**: `X-Excalidraw-*` (Excalidraw)、`X-Visio-*` (Visio)、`X-MindMeister-*` (MindMeister)、`X-FigJam-*`/`X-tldraw-*`/`X-Diagrams-*`/`X-Gliffy-*`/`X-XMind-*`/`X-MindNode-*`/`X-Mindomo-*`/`X-Coggle-*`/`X-MindMup-*`/`X-Bubbl-*`/`X-Stormboard-*`/`X-Ayoa-*`/`X-Creately-*`/`X-Milanote-*`/`X-Conceptboard-*`/`X-Padlet-*`/`X-Jamboard-*`/`X-Ziteboard-*`/`X-Awesome-Table-*` は図機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `diagram_marks` + `has_diagram_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 図印の自署を問え。

### Security — D509: `X-Retool-*`/`X-Supabase-*`/`X-Strapi-*`/`X-Budibase-*`/`X-NocoDB-*`/`X-Contentful-*` 等のローコード・社内ツール・ヘッドレス CMS 印自称が未検査

- **問題**: `X-Retool-*` (Retool)、`X-Supabase-*` (Supabase)、`X-Strapi-*` (Strapi)、`X-SmartSuite-*`/`X-Baserow-*`/`X-NocoDB-*`/`X-AppSheet-*`/`X-Budibase-*`/`X-Appsmith-*`/`X-ToolJet-*`/`X-Zenkit-*`/`X-Fibery-*`/`X-Softr-*`/`X-Stacker-*`/`X-Glide-*`/`X-Adalo-*`/`X-Thunkable-*`/`X-Bubble-*`/`X-DrapCode-*`/`X-WeWeb-*`/`X-Xano-*`/`X-Appwrite-*`/`X-PocketBase-*`/`X-Directus-*`/`X-Keystone-*`/`X-Sanity-*`/`X-Contentful-*`/`X-Prismic-*`/`X-Storyblok-*`/`X-DatoCMS-*`/`X-Hygraph-*`/`X-TinaCMS-*`/`X-Decap-*`/`X-Forestry-*` は内機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `lowcode_marks` + `has_lowcode_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 内印の自署を問え。


### Security — D504: `X-Drone-*`/`X-Concourse-*`/`X-Bazel-*`/`X-Gradle-*`/`X-AppVeyor-*`/`X-Webpack-*` 等の CI/CD・ビルド・バンドラ印自称が未検査

- **問題**: `X-Drone-*` (Drone)、`X-Concourse-*` (Concourse)、`X-Bazel-*` (Bazel)、`X-Semaphore-*`/`X-Woodpecker-*`/`X-GoCD-*`/`X-Bamboo-*`/`X-AppVeyor-*`/`X-AzurePipelines-*`/`X-AzureDevOps-*`/`X-Bitbucket-Pipelines-*`/`X-Bitrise-*`/`X-Codemagic-*`/`X-fastlane-*`/`X-Gradle-*`/`X-Maven-*`/`X-sbt-*`/`X-CMake-*`/`X-Buck-*`/`X-Pants-*`/`X-Nx-*`/`X-Turborepo-*`/`X-Lerna-*`/`X-Rush-*`/`X-esbuild-*`/`X-SWC-*`/`X-Vite-*`/`X-Rollup-*`/`X-Webpack-*`/`X-Parcel-*`/`X-Snowpack-*`/`X-Rome-*`/`X-Biome-*`/`X-OXC-*`/`X-dprint-*`/`X-Prettier-*`/`X-ESLint-*`/`X-Stylelint-*` は構築機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `ci_marks` + `has_ci_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 構築印の自署を問え。

### Security — D505: `X-CodeQL-*`/`X-Dependabot-*`/`X-Trivy-*`/`X-Renovate-*`/`X-Semgrep-*`/`X-Wiz-*` 等のコード品質・依存・コンテナセキュリティ印自称が未検査

- **問題**: `X-CodeQL-*` (CodeQL)、`X-Dependabot-*` (Dependabot)、`X-Trivy-*` (Trivy)、`X-Codacy-*`/`X-CodeClimate-*`/`X-DeepSource-*`/`X-Coverity-*`/`X-Fortify-*`/`X-Mend-*`/`X-WhiteSource-*`/`X-Renovate-*`/`X-Grype-*`/`X-Syft-*`/`X-Clair-*`/`X-Twistlock-*`/`X-Prisma-*`/`X-Wiz-*`/`X-Orca-*`/`X-Lacework-*`/`X-Sysdig-*`/`X-Falco-*`/`X-Semgrep-*` は検査機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `codequality_marks` + `has_codequality_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 検査印の自署を問え。

### Security — D506: `X-npmjs-*`/`X-PyPI-*`/`X-Docker-Hub-*`/`X-Homebrew-*`/`X-NuGet-*`/`X-GHCR-*` 等のパッケージ・レジストリ印自称が未検査

- **問題**: `X-npmjs-*` (npm)、`X-PyPI-*` (PyPI)、`X-Docker-Hub-*` (Docker Hub)、`X-RubyGems-*`/`X-NuGet-*`/`X-Packagist-*`/`X-Homebrew-*`/`X-Chocolatey-*`/`X-Scoop-*`/`X-winget-*`/`X-Flatpak-*`/`X-Snapcraft-*`/`X-AppImage-*`/`X-Nixpkgs-*`/`X-Conda-*`/`X-Anaconda-*`/`X-DockerHub-*`/`X-Quay-*`/`X-GHCR-*`/`X-Harbor-*`/`X-Nexus-*`/`X-Verdaccio-*`/`X-Yarn-*`/`X-pnpm-*`/`X-Composer-*`/`X-Poetry-*`/`X-Pipenv-*`/`X-CocoaPods-*`/`X-Carthage-*`/`X-SPM-*`/`X-pub-*`/`X-Hex-*`/`X-CPAN-*`/`X-CRAN-*`/`X-Clojars-*`/`X-vcpkg-*`/`X-Conan-*` は庫機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `package_marks` + `has_package_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 庫印の自署を問え。


### Security — D501: `X-GoDaddy-*`/`X-Namecheap-*`/`X-DNSimple-*`/`X-Porkbun-*`/`X-Gandi-*`/`X-Route53-*` 等の DNS・ドメイン・DDNS 印自称が未検査

- **問題**: `X-GoDaddy-*` (GoDaddy)、`X-Namecheap-*` (Namecheap)、`X-DNSimple-*` (DNSimple)、`X-Porkbun-*`/`X-Dynadot-*`/`X-Gandi-*`/`X-NetworkSolutions-*`/`X-eNom-*`/`X-Tucows-*`/`X-Register-*`/`X-MarkMonitor-*`/`X-CSCGlobal-*`/`X-BrandShield-*`/`X-Versio-*`/`X-TransIP-*`/`X-Epik-*`/`X-Joker-*`/`X-NameBay-*`/`X-NameSilo-*`/`X-EuroDNS-*`/`X-easyDNS-*`/`X-Hover-*`/`X-No-IP-*`/`X-Afraid-*`/`X-ChangeIP-*`/`X-DDNS-*`/`X-DuckDNS-*`/`X-Dynu-*`/`X-FreeDNS-*`/`X-Route53-*`/`X-AzureDNS-*`/`X-GoogleDomains-*`/`X-CloudflareDNS-*` は名簿機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `domain_marks` + `has_domain_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 名簿印の自署を問え。

### Security — D502: `X-DreamHost-*`/`X-Bluehost-*`/`X-HostGator-*`/`X-SiteGround-*`/`X-Hostinger-*`/`X-Cloudways-*` 等のウェブホスティング印自称が未検査

- **問題**: `X-DreamHost-*` (DreamHost)、`X-Bluehost-*` (Bluehost)、`X-HostGator-*` (HostGator)、`X-SiteGround-*`/`X-A2Hosting-*`/`X-InMotion-*`/`X-Hostinger-*`/`X-HostPapa-*`/`X-GreenGeeks-*`/`X-NearlyFreeSpeech-*`/`X-Hostwinds-*`/`X-LiquidWeb-*`/`X-Nexcess-*`/`X-Flywheel-*`/`X-Cloudways-*`/`X-Pressable-*`/`X-Interserver-*`/`X-NameHero-*`/`X-Verpex-*`/`X-ChemiCloud-*`/`X-ScalaHosting-*`/`X-TMDHosting-*`/`X-AccuWeb-*`/`X-MilesWeb-*`/`X-BigRock-*`/`X-ResellerClub-*` は宿機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `webhost_marks` + `has_webhost_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 宿印の自署を問え。

### Security — D503: `X-Proton-*`/`X-Tutanota-*`/`X-Fastmail-*`/`X-Runbox-*`/`X-Migadu-*`/`X-Posteo-*` 等のプライバシーメール印自称が未検査

- **問題**: `X-Proton-*` (Proton)、`X-Tutanota-*` (Tutanota)、`X-Fastmail-*` (Fastmail)、`X-ProtonMail-*`/`X-Tuta-*`/`X-Runbox-*`/`X-Posteo-*`/`X-Migadu-*`/`X-Purelymail-*`/`X-Hushmail-*`/`X-Countermail-*`/`X-Mailfence-*`/`X-StartMail-*`/`X-Disroot-*`/`X-Systemli-*`/`X-Autistici-*`/`X-Riseup-*`/`X-Pobox-*`/`X-Hey-*`/`X-Cock-*`/`X-Lavabit-*` は秘匿機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `mailprivacy_marks` + `has_mailprivacy_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 秘匿印の自署を問え。


### Security — D498: `X-Arduino-*`/`X-Prusa-*`/`X-JLCPCB-*`/`X-ESP32-*`/`X-Particle-*`/`X-ThingSpeak-*` 等の IoT・3D プリント・電子部品印自称が未検査

- **問題**: `X-Arduino-*` (Arduino)、`X-Prusa-*` (Prusa)、`X-JLCPCB-*` (JLCPCB)、`X-RaspberryPi-*`/`X-ESP32-*`/`X-Particle-*`/`X-Blynk-*`/`X-ThingSpeak-*`/`X-Adafruit-*`/`X-SparkFun-*`/`X-Tindie-*`/`X-Seeed-*`/`X-Pololu-*`/`X-DFRobot-*`/`X-Pimoroni-*`/`X-Elegoo-*`/`X-Creality-*`/`X-Bambu-*`/`X-Anycubic-*`/`X-Ultimaker-*`/`X-Formlabs-*`/`X-Markforged-*`/`X-Stratasys-*`/`X-3DSystems-*`/`X-Materialise-*`/`X-Shapeways-*`/`X-Sculpteo-*`/`X-Protolabs-*`/`X-Xometry-*`/`X-Fictiv-*`/`X-Hubs-*`/`X-PCBWay-*`/`X-OSH-Park-*`/`X-Aisler-*`/`X-Eurocircuits-*`/`X-DigiKey-*`/`X-Mouser-*`/`X-Farnell-*`/`X-RSComponents-*`/`X-Avnet-*`/`X-Arrow-*`/`X-TME-*` は製造機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `maker_marks` + `has_maker_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 製造印の自署を問え。

### Security — D499: `X-Nagios-*`/`X-Zabbix-*`/`X-Graylog-*`/`X-InfluxDB-*`/`X-Fluentd-*`/`X-SolarWinds-*` 等の監視・ログ基盤印自称が未検査

- **問題**: `X-Nagios-*` (Nagios)、`X-Zabbix-*` (Zabbix)、`X-Graylog-*` (Graylog)、`X-SolarWinds-*`/`X-PRTG-*`/`X-Icinga-*`/`X-Checkmk-*`/`X-LibreNMS-*`/`X-Observium-*`/`X-Cacti-*`/`X-Munin-*`/`X-collectd-*`/`X-Telegraf-*`/`X-InfluxDB-*`/`X-TimescaleDB-*`/`X-VictoriaMetrics-*`/`X-Mimir-*`/`X-Thanos-*`/`X-Cortex-*`/`X-Loki-*`/`X-Elasticsearch-*`/`X-OpenSearch-*`/`X-Mezmo-*`/`X-LogDNA-*`/`X-Scalyr-*`/`X-Fluentd-*`/`X-Logstash-*`/`X-Vector-*`/`X-Filebeat-*`/`X-rsyslog-*`/`X-syslog-ng-*`/`X-journald-*` は監視機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `monitoring_marks` + `has_monitoring_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 監視印の自署を問え。

### Security — D500: `X-Postman-*`/`X-VisualStudio-*`/`X-Statuspage-*`/`X-Xcode-*`/`X-IntelliJ-*`/`X-OhDear-*` 等の IDE・エディタ・API・稼働監視ツール印自称が未検査

- **問題**: `X-Postman-*` (Postman)、`X-VisualStudio-*` (Visual Studio)、`X-Statuspage-*` (Statuspage)、`X-Xcode-*`/`X-AndroidStudio-*`/`X-IntelliJ-*`/`X-WebStorm-*`/`X-PhpStorm-*`/`X-PyCharm-*`/`X-RubyMine-*`/`X-GoLand-*`/`X-CLion-*`/`X-Rider-*`/`X-DataGrip-*`/`X-Aqua-*`/`X-Fleet-*`/`X-Eclipse-*`/`X-NetBeans-*`/`X-VSCode-*`/`X-VSCodium-*`/`X-Zed-*`/`X-Nova-*`/`X-BBEdit-*`/`X-TextMate-*`/`X-Sublime-*`/`X-Emacs-*`/`X-Vim-*`/`X-Neovim-*`/`X-Helix-*`/`X-Micro-*`/`X-Kakoune-*`/`X-JetBrains-*`/`X-Insomnia-*`/`X-HTTPie-*`/`X-Paw-*`/`X-RapidAPI-*`/`X-Checkly-*`/`X-Runscope-*`/`X-BetterStack-*`/`X-Cachet-*`/`X-Upptime-*`/`X-Site24x7-*`/`X-Freshping-*`/`X-HetrixTools-*`/`X-NodePing-*`/`X-Pulsetic-*`/`X-Hyperping-*`/`X-OhDear-*` はツール機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `devtools_marks` + `has_devtools_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — ツール印の自署を問え。


### Security — D495: `X-AWS-*`/`X-Azure-*`/`X-GoogleCloud-*`/`X-Alibaba-*`/`X-Oracle-Cloud-*`/`X-IBMCloud-*` 等のクラウドプラットフォーム印自称が未検査

- **問題**: `X-AWS-*` (Amazon Web Services)、`X-Azure-*` (Microsoft Azure)、`X-GoogleCloud-*` (Google Cloud)、`X-AmazonSES-*`/`X-GCP-*`/`X-Alibaba-*`/`X-Baidu-*`/`X-Oracle-Cloud-*`/`X-IBMCloud-*` はクラウド機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `cloudprovider_marks` + `has_cloudprovider_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — クラウド印の自署を問え。

### Security — D496: `X-Samsung-*`/`X-Sony-*`/`X-Canon-*`/`X-Panasonic-*`/`X-Xiaomi-*`/`X-Nikon-*` 等のスマートフォン・家電メーカー印自称が未検査

- **問題**: `X-Samsung-*` (Samsung)、`X-Sony-*` (Sony)、`X-Canon-*` (Canon)、`X-Xiaomi-*`/`X-OPPO-*`/`X-vivo-*`/`X-HONOR-*`/`X-OnePlus-*`/`X-realme-*`/`X-Panasonic-*`/`X-SHARP-*`/`X-TOSHIBA-*`/`X-Hitachi-*`/`X-NEC-*`/`X-Fujitsu-*`/`X-FUJIFILM-*`/`X-OLYMPUS-*`/`X-Nikon-*`/`X-Ricoh-*`/`X-KYOCERA-*`/`X-EPSON-*`/`X-Brother-*`/`X-CASIO-*`/`X-SEIKO-*`/`X-CITIZEN-*` はメーカーの通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `device_marks` + `has_device_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — メーカー印の自署を問え。

### Security — D497: `X-YAMAHA-*`/`X-Ableton-*`/`X-Steinberg-*`/`X-Roland-*`/`X-iZotope-*`/`X-Waves-*` 等の音楽制作・オーディオ印自称が未検査

- **問題**: `X-YAMAHA-*` (YAMAHA)、`X-Ableton-*` (Ableton)、`X-Steinberg-*` (Steinberg)、`X-KAWAI-*`/`X-Roland-*`/`X-KORG-*`/`X-Akai-*`/`X-Novation-*`/`X-Native-Instruments-*`/`X-Focusrite-*`/`X-Universal-Audio-*`/`X-Apogee-*`/`X-MOTU-*`/`X-PreSonus-*`/`X-Avid-*`/`X-ProTools-*`/`X-Logic-*`/`X-Cubase-*`/`X-FLStudio-*`/`X-Reason-*`/`X-Bitwig-*`/`X-StudioOne-*`/`X-Ardour-*`/`X-REAPER-*`/`X-Audacity-*`/`X-GarageBand-*`/`X-Soundtrap-*`/`X-BandLab-*`/`X-Splice-*`/`X-Loopcloud-*`/`X-LANDR-*`/`X-eMastered-*`/`X-Ozone-*`/`X-iZotope-*`/`X-Waves-*`/`X-FabFilter-*`/`X-Valhalla-*`/`X-Soundtoys-*`/`X-PluginBoutique-*`/`X-Kilohearts-*`/`X-Cableguys-*`/`X-Output-*`/`X-Heavyocity-*`/`X-Spitfire-*`/`X-Soniccouture-*`/`X-Vienna-*`/`X-EastWest-*`/`X-Cinesamples-*`/`X-ProjectSAM-*`/`X-8Dio-*` は音響機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `audio_marks` + `has_audio_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 音響印の自署を問え。


### Security — D492: `X-GitBook-*`/`X-WordPress-*`/`X-Ghost-*`/`X-Replit-*`/`X-StackBlitz-*`/`X-Feedly-*` 等のドキュメント・静的サイト印自称が未検査

- **問題**: `X-GitBook-*` (GitBook)、`X-WordPress-*` (WordPress)、`X-Ghost-*` (Ghost)、`X-Docusaurus-*`/`X-MkDocs-*`/`X-Sphinx-*`/`X-Jekyll-*`/`X-Hugo-*`/`X-Gatsby-*`/`X-Surge-*`/`X-Cyclic-*`/`X-Glitch-*`/`X-Replit-*`/`X-CodeSandbox-*`/`X-StackBlitz-*`/`X-CodePen-*`/`X-JSFiddle-*`/`X-Plunker-*`/`X-Observable-*`/`X-Deepnote-*`/`X-Hexo-*`/`X-Bloglovin-*`/`X-Feedly-*`/`X-Inoreader-*`/`X-NewsBlur-*` は文書機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `docsite_marks` + `has_docsite_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 文書印の自署を問え。

### Security — D493: `X-SoundCloud-*`/`X-Acast-*`/`X-DistroKid-*`/`X-Bandcamp-*`/`X-TuneCore-*`/`X-Deezer-*` 等のポッドキャスト・音楽印自称が未検査

- **問題**: `X-SoundCloud-*` (SoundCloud)、`X-Acast-*` (Acast)、`X-DistroKid-*` (DistroKid)、`X-Podpage-*`/`X-Captivate-*`/`X-Transistor-*`/`X-Megaphone-*`/`X-Omny-*`/`X-Art19-*`/`X-iVoox-*`/`X-Audioboom-*`/`X-Mixcloud-*`/`X-HearThis-*`/`X-AudioMack-*`/`X-Bandcamp-*`/`X-TuneCore-*`/`X-CDBaby-*`/`X-Amuse-*`/`X-UnitedMasters-*`/`X-Deezer-*`/`X-Tidal-*`/`X-Pandora-*`/`X-iHeartRadio-*`/`X-AmazonMusic-*`/`X-YouTubeMusic-*`/`X-Audius-*` は音楽機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `music_marks` + `has_music_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 音楽印の自署を問え。

### Security — D494: `X-Walmart-*`/`X-Newegg-*`/`X-Logitech-*`/`X-Shopware-*`/`X-Medusa-*`/`X-Anker-*` 等の EC・PC パーツ印自称が未検査

- **問題**: `X-Walmart-*` (Walmart)、`X-Newegg-*` (Newegg)、`X-Logitech-*` (Logitech)、`X-EasyStore-*`/`X-MyShop-*`/`X-SHOPLINE-*`/`X-Cafe24-*`/`X-CubeCart-*`/`X-ZenCart-*`/`X-osCommerce-*`/`X-VirtueMart-*`/`X-HikaShop-*`/`X-Shopware-*`/`X-Sylius-*`/`X-Swell-*`/`X-Medusa-*`/`X-Saleor-*`/`X-Vendure-*`/`X-Commerce.js-*`/`X-ElasticPath-*`/`X-Fabric-*`/`X-commercetools-*`/`X-Bolcom-*`/`X-Rakuma-*`/`X-Auctions-*`/`X-Target-*`/`X-Costco-*`/`X-BestBuy-*`/`X-Adorama-*`/`X-MicroCenter-*`/`X-Monoprice-*`/`X-Keychron-*`/`X-Varmilo-*`/`X-Leopold-*`/`X-Filco-*`/`X-DasKeyboard-*`/`X-Razer-*`/`X-Corsair-*`/`X-SteelSeries-*`/`X-HyperX-*`/`X-Elgato-*`/`X-Aukey-*`/`X-Anker-*`/`X-Belkin-*`/`X-Ugreen-*`/`X-Satechi-*`/`X-Twelve-South-*`/`X-mophie-*`/`X-Native-Union-*`/`X-Moment-*`/`X-Peak-Design-*`/`X-Thule-*` は販売機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `retail_marks` + `has_retail_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 販売印の自署を問え。


### Security — D489: `X-Expensify-*`/`X-Ramp-*`/`X-Concur-*`/`X-Pleo-*`/`X-Navan-*`/`X-Dext-*` 等の経費・精算印自称が未検査

- **問題**: `X-Expensify-*` (Expensify)、`X-Ramp-*` (Ramp)、`X-Concur-*` (SAP Concur)、`X-Bill-*`/`X-Pleo-*`/`X-Divvy-*`/`X-Navan-*`/`X-TripActions-*`/`X-Coupa-*`/`X-Procurify-*`/`X-Certify-*`/`X-Chrome-River-*`/`X-Abacus-*`/`X-Fyle-*`/`X-Zoho-Expense-*`/`X-Dext-*`/`X-AutoEntry-*`/`X-Hubdoc-*`/`X-Receipt-Bank-*`/`X-Veryfi-*`/`X-Datamolino-*`/`X-Nanonets-*`/`X-Klippa-*` は経費機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `expense_marks` + `has_expense_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 経費印の自署を問え。

### Security — D490: `X-Zapier-*`/`X-n8n-*`/`X-Fivetran-*`/`X-IFTTT-*`/`X-Workato-*`/`X-Airbyte-*` 等の自動化・データパイプライン印自称が未検査

- **問題**: `X-Zapier-*` (Zapier)、`X-n8n-*` (n8n)、`X-Fivetran-*` (Fivetran)、`X-DocParser-*`/`X-Parsio-*`/`X-MailParser-*`/`X-Make-*`/`X-Integromat-*`/`X-IFTTT-*`/`X-Workato-*`/`X-Tray-*`/`X-MuleSoft-*`/`X-Boomi-*`/`X-Informatica-*`/`X-Talend-*`/`X-Airbyte-*`/`X-Stitch-*`/`X-Hevo-*`/`X-RudderStack-*`/`X-mParticle-*`/`X-Tealium-*`/`X-Lytics-*`/`X-Insider-*`/`X-Optimove-*` は自動化機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `automation_marks` + `has_automation_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 自動化印の自署を問え。

### Security — D491: `X-Hotjar-*`/`X-FullStory-*`/`X-Pendo-*`/`X-Survicate-*`/`X-WalkMe-*`/`X-Appcues-*` 等の顧客体験・アンケート印自称が未検査

- **問題**: `X-Hotjar-*` (Hotjar)、`X-FullStory-*` (FullStory)、`X-Pendo-*` (Pendo)、`X-NICE-*`/`X-InMoment-*`/`X-Momentive-*`/`X-AskNicely-*`/`X-Delighted-*`/`X-Retently-*`/`X-SatisMeter-*`/`X-Promoter-*`/`X-Wootric-*`/`X-SimpleSat-*`/`X-CustomerThermometer-*`/`X-Zenloop-*`/`X-Startquestion-*`/`X-Questback-*`/`X-Alchemer-*`/`X-SurveyGizmo-*`/`X-SmartSurvey-*`/`X-Survicate-*`/`X-CrazyEgg-*`/`X-Mouseflow-*`/`X-LuckyOrange-*`/`X-Smartlook-*`/`X-Contentsquare-*`/`X-Quantum-Metric-*`/`X-Glassbox-*`/`X-Decibel-*`/`X-Usabilla-*`/`X-UserVoice-*`/`X-Qualaroo-*`/`X-UserReport-*`/`X-WalkMe-*`/`X-Userlane-*`/`X-Appcues-*`/`X-Chameleon-*`/`X-Userpilot-*`/`X-CustomerGauge-*` は顧客体験機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `cx_marks` + `has_cx_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 顧客体験印の自署を問え。


### Security — D486: `X-Telegram-*`/`X-WhatsApp-*`/`X-Mattermost-*`/`X-Element-*`/`X-Chatwoot-*`/`X-BlueJeans-*` 等のチャット・会議印自称が未検査

- **問題**: `X-Telegram-*` (Telegram)、`X-WhatsApp-*` (WhatsApp)、`X-Mattermost-*` (Mattermost)、`X-Olark-*`/`X-Tawk-*`/`X-Crisp-*`/`X-Chatwoot-*`/`X-HelpCrunch-*`/`X-SnapEngage-*`/`X-Rocket-*`/`X-Element-*`/`X-Matrix-*`/`X-Signal-*`/`X-Viber-*`/`X-WeChat-*`/`X-Teams-*`/`X-Meet-*`/`X-Chime-*`/`X-BlueJeans-*`/`X-GoToWebinar-*`/`X-WebinarJam-*`/`X-Crowdcast-*`/`X-Hopin-*`/`X-Rally-*` は会議機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `meeting_marks` + `has_meeting_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 会議印の自署を問え。

### Security — D487: `X-Doodle-*`/`X-Acuity-*`/`X-Mindbody-*`/`X-Vagaro-*`/`X-Fresha-*`/`X-Trainerize-*` 等の予約・スケジューリング印自称が未検査

- **問題**: `X-Doodle-*` (Doodle)、`X-Acuity-*` (Acuity Scheduling)、`X-Mindbody-*` (Mindbody)、`X-Appointlet-*`/`X-Bookings-*`/`X-Vagaro-*`/`X-Booksy-*`/`X-Fresha-*`/`X-SimplyBook-*`/`X-Setmore-*`/`X-YouCanBook-*`/`X-Coconut-*`/`X-Momence-*`/`X-Pike13-*`/`X-Glofox-*`/`X-WellnessLiving-*`/`X-ZenPlanner-*`/`X-Wodify-*`/`X-PushPress-*`/`X-TrainHeroic-*`/`X-TeamBuildr-*`/`X-PTDistinction-*`/`X-Trainerize-*`/`X-Everfit-*` は予約機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `booking_marks` + `has_booking_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 予約印の自署を問え。

### Security — D488: `X-ServiceTitan-*`/`X-Jobber-*`/`X-UpKeep-*`/`X-Housecall-*`/`X-MaintainX-*`/`X-Workiz-*` 等のフィールドサービス・設備管理印自称が未検査

- **問題**: `X-ServiceTitan-*` (ServiceTitan)、`X-Jobber-*` (Jobber)、`X-UpKeep-*` (UpKeep)、`X-Housecall-*`/`X-FieldEdge-*`/`X-ServiceFusion-*`/`X-Workiz-*`/`X-ServiceChannel-*`/`X-Limble-*`/`X-Fiix-*`/`X-eMaint-*`/`X-MPulse-*`/`X-Fracttal-*`/`X-MaintainX-*`/`X-Hippo-*`/`X-BlueFolder-*`/`X-Corrigo-*`/`X-WebTMA-*`/`X-MainSim-*`/`X-eAM-*`/`X-CMMS-*`/`X-MEX-*`/`X-FMX-*`/`X-ManagerPlus-*`/`X-Reach-*` は設備管理機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `fieldservice_marks` + `has_fieldservice_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 設備管理印の自署を問え。


### Security — D483: `X-OneDrive-*`/`X-SharePoint-*`/`X-GoogleDrive-*`/`X-Nextcloud-*`/`X-WeTransfer-*`/`X-Egnyte-*` 等のファイル共有・クラウドストレージ印自称が未検査

- **問題**: `X-OneDrive-*` (OneDrive)、`X-SharePoint-*` (SharePoint)、`X-GoogleDrive-*` (Google Drive)、`X-Egnyte-*`/`X-Druva-*`/`X-Sync-*`/`X-pCloud-*`/`X-Nextcloud-*`/`X-ownCloud-*`/`X-Seafile-*`/`X-Koofr-*`/`X-WeTransfer-*`/`X-Resilio-*` はストレージ機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `storage_marks` + `has_storage_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — ストレージ印の自署を問え。

### Security — D484: `X-Framer-*`/`X-Zeplin-*`/`X-Sketch-*`/`X-Photoshop-*`/`X-Illustrator-*`/`X-DaVinci-*` 等のデザイン・クリエイティブ印自称が未検査

- **問題**: `X-Framer-*` (Framer)、`X-Zeplin-*` (Zeplin)、`X-Sketch-*` (Sketch)、`X-Lucidspark-*`/`X-drawio-*`/`X-Abstract-*`/`X-Avocode-*`/`X-Marvel-*`/`X-UXPin-*`/`X-Origami-*`/`X-Principle-*`/`X-Affinity-*`/`X-CorelDRAW-*`/`X-Photoshop-*`/`X-Illustrator-*`/`X-InDesign-*`/`X-Lightroom-*`/`X-Premiere-*`/`X-AfterEffects-*`/`X-DaVinci-*`/`X-FFmpeg-*`/`X-OBS-*`/`X-Streamlabs-*`/`X-Procreate-*`/`X-Clip-*`/`X-Blender-*` は制作機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `creative_marks` + `has_creative_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 制作印の自署を問え。

### Security — D485: `X-Qiita-*`/`X-Zenn-*`/`X-Backlog-*`/`X-Kibela-*`/`X-Taiga-*`/`X-Pipedrive-*` 等のナレッジ・タスク管理・CRM 印自称が未検査

- **問題**: `X-Qiita-*` (Qiita)、`X-Zenn-*` (Zenn)、`X-Backlog-*` (Backlog)、`X-Cacoo-*`/`X-Kibela-*`/`X-Note-*`/`X-Planio-*`/`X-OpenProject-*`/`X-Taiga-*`/`X-Wekan-*`/`X-Vivify-*`/`X-YouGile-*`/`X-Launchpad-*`/`X-Codeberg-*`/`X-SourceForge-*`/`X-Podio-*`/`X-Zoho-*`/`X-Freshworks-*`/`X-Pipedrive-*`/`X-Insightly-*`/`X-Capsule-*`/`X-Streak-*`/`X-Nimble-*`/`X-SugarCRM-*`/`X-Obsidian-*`/`X-OneNote-*`/`X-AnyDo-*`/`X-TickTick-*`/`X-Microsoft-Todo-*` は管理機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `project_marks` + `has_project_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 管理印の自署を問え。


### Security — D480: `X-Zillow-*`/`X-Redfin-*`/`X-Rightmove-*`/`X-SUUMO-*`/`X-Idealista-*`/`X-Zoopla-*` 等の不動産・ホームサービス印自称が未検査

- **問題**: `X-Zillow-*` (Zillow)、`X-Redfin-*` (Redfin)、`X-Rightmove-*` (Rightmove)、`X-Realtor-*`/`X-Trulia-*`/`X-Apartments-*`/`X-Zumper-*`/`X-Compass-*`/`X-Opendoor-*`/`X-LoopNet-*`/`X-CoStar-*`/`X-Idealista-*`/`X-Immobiliare-*`/`X-Fotocasa-*`/`X-Zoopla-*`/`X-OnTheMarket-*`/`X-PrimeLocation-*`/`X-SpareRoom-*`/`X-OpenRent-*`/`X-Realestate-*`/`X-Domain-*`/`X-Homely-*`/`X-Allhomes-*`/`X-Lianjia-*`/`X-Beike-*`/`X-Anjuke-*`/`X-Ziroom-*`/`X-SUUMO-*`/`X-LIFULL-*`/`X-athome-*` は不動産機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `realestate_marks` + `has_realestate_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 不動産印の自署を問え。

### Security — D481: `X-Zocdoc-*`/`X-GoodRx-*`/`X-Doximity-*`/`X-LabCorp-*`/`X-Ancestry-*`/`X-MyChart-*` 等のヘルスケア・薬局・DNA 検査印自称が未検査

- **問題**: `X-Zocdoc-*` (Zocdoc)、`X-GoodRx-*` (GoodRx)、`X-Doximity-*` (Doximity)、`X-LabCorp-*`/`X-Quest-*`/`X-MyChart-*`/`X-FollowMyHealth-*`/`X-Ancestry-*`/`X-MyHeritage-*`/`X-23andMe-*`/`X-Invitae-*`/`X-Natera-*`/`X-SingleCare-*`/`X-Hims-*`/`X-Optum-*`/`X-CVS-*`/`X-Walgreens-*`/`X-Cigna-*`/`X-Aetna-*`/`X-Humana-*`/`X-Anthem-*`/`X-Kaiser-*`/`X-Oscar-*`/`X-Cerner-*`/`X-OracleHealth-*` は医療機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `health_marks` + `has_health_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 医療印の自署を問え。

### Security — D482: `X-Indeed-*`/`X-Glassdoor-*`/`X-ZipRecruiter-*`/`X-Wellfound-*`/`X-Mynavi-*`/`X-doda-*` 等の求職・人材印自称が未検査

- **問題**: `X-Indeed-*` (Indeed)、`X-Glassdoor-*` (Glassdoor)、`X-ZipRecruiter-*` (ZipRecruiter)、`X-Monster-*`/`X-CareerBuilder-*`/`X-Dice-*`/`X-Wellfound-*`/`X-Randstad-*`/`X-Adecco-*`/`X-Manpower-*`/`X-Kforce-*`/`X-RobertHalf-*`/`X-Hays-*`/`X-PageGroup-*`/`X-Pasona-*`/`X-en-japan-*`/`X-Mynavi-*`/`X-doda-*`/`X-GaijinPot-*`/`X-Daijob-*` は人材機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `jobs_marks` + `has_jobs_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 人材印の自署を問え。


### Security — D477: `X-Coursera-*`/`X-Duolingo-*`/`X-HackerRank-*`/`X-Udemy-*`/`X-Canvas-*`/`X-Blackboard-*` 等の教育・LMS 印自称が未検査

- **問題**: `X-Coursera-*` (Coursera)、`X-Duolingo-*` (Duolingo)、`X-HackerRank-*` (HackerRank)、`X-Udemy-*`/`X-edX-*`/`X-Udacity-*`/`X-Pluralsight-*`/`X-Skillshare-*`/`X-DataCamp-*`/`X-Codecademy-*`/`X-LeetCode-*`/`X-CodeWars-*`/`X-Exercism-*`/`X-Topcoder-*`/`X-Codeforces-*`/`X-KhanAcademy-*`/`X-Brilliant-*`/`X-Canvas-*`/`X-Instructure-*`/`X-Blackboard-*`/`X-D2L-*` は教育機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `edu_marks` + `has_edu_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 教育印の自署を問え。

### Security — D478: `X-EchoSign-*`/`X-PandaDoc-*`/`X-HelloSign-*`/`X-OneSpan-*`/`X-Yousign-*`/`X-Ironclad-*` 等の電子署名・契約管理印自称が未検査

- **問題**: `X-EchoSign-*` (Adobe Sign)、`X-OneSpan-*` (OneSpan)、`X-PandaDoc-*` (PandaDoc)、`X-AdobeSign-*`/`X-HelloSign-*`/`X-DropboxSign-*`/`X-SignNow-*`/`X-RightSignature-*`/`X-SignRequest-*`/`X-Yousign-*`/`X-Oneflow-*`/`X-GetAccept-*`/`X-Juro-*`/`X-Ironclad-*`/`X-Evisort-*`/`X-Icertis-*`/`X-Agiloft-*`/`X-Conga-*`/`X-Namirial-*`/`X-Skribble-*`/`X-ZohoSign-*`/`X-pdfFiller-*`/`X-LexisNexis-*`/`X-WoltersKluwer-*` は契約機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `esign_marks` + `has_esign_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 契約印の自署を問え。

### Security — D479: `X-GoFundMe-*`/`X-Kickstarter-*`/`X-Indiegogo-*`/`X-Ko-fi-*`/`X-JustGiving-*`/`X-Blackbaud-*` 等のクラウドファンディング・寄付印自称が未検査

- **問題**: `X-GoFundMe-*` (GoFundMe)、`X-Kickstarter-*` (Kickstarter)、`X-Indiegogo-*` (Indiegogo)、`X-Ko-fi-*`/`X-BuyMeACoffee-*`/`X-OpenCollective-*`/`X-JustGiving-*`/`X-Crowdfunder-*`/`X-Blackbaud-*`/`X-Bloomerang-*`/`X-Kindful-*`/`X-Donorbox-*`/`X-Qgiv-*`/`X-Givebutter-*`/`X-Fundly-*`/`X-Mightycause-*` は寄付機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `donation_marks` + `has_donation_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 寄付印の自署を問え。


### Security — D474: `X-Okta-*`/`X-Auth0-*`/`X-CrowdStrike-*`/`X-Snyk-*`/`X-HashiCorp-*`/`X-Bitbucket-*` 等の開発・ID・セキュリティ SaaS 印自称が未検査

- **問題**: `X-Okta-*` (Okta)、`X-CrowdStrike-*` (CrowdStrike)、`X-Snyk-*` (Snyk)、`X-Auth0-*`/`X-PingIdentity-*`/`X-OneLogin-*`/`X-Duo-*` (ID)、`X-CyberArk-*`/`X-BeyondTrust-*`/`X-HashiCorp-*`/`X-Pulumi-*`/`X-Docker-*`/`X-Bitbucket-*`/`X-TeamCity-*`/`X-Buildkite-*`/`X-Octopus-*`/`X-SonarCloud-*`/`X-SonarQube-*`/`X-JFrog-*`/`X-Sonatype-*`/`X-Veracode-*`/`X-Checkmarx-*`/`X-SentinelOne-*`/`X-Cybereason-*`/`X-Tanium-*`/`X-PaloAlto-*`/`X-PANW-*`/`X-Mandiant-*` は業務 SaaS 機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `enterprise_saas_marks` + `has_enterprise_saas_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 業務 SaaS 印の自署を問え。

### Security — D475: `X-FedEx-*`/`X-DHL-*`/`X-UPS-*`/`X-USPS-*`/`X-JapanPost-*`/`X-Yamato-*` 等の宅配・物流印自称が未検査

- **問題**: `X-FedEx-*` (FedEx)、`X-DHL-*` (DHL)、`X-JapanPost-*` (日本郵便)、`X-UPS-*`/`X-USPS-*`/`X-DPD-*`/`X-GLS-*`/`X-Evri-*`/`X-RoyalMail-*`/`X-PostNL-*`/`X-bpost-*`/`X-Colissimo-*`/`X-Chronopost-*`/`X-InPost-*`/`X-Correos-*`/`X-PostNord-*`/`X-CanadaPost-*`/`X-AusPost-*`/`X-Yamato-*`/`X-Sagawa-*`/`X-Cainiao-*`/`X-AfterShip-*`/`X-EasyPost-*`/`X-Shippo-*`/`X-ShipStation-*` は配送機の発信記録 — 送信側が書くことは自称。配送通知の偽装はフィッシングの典型手口。
- **修正**: `Envelope` に `shipping_marks` + `has_shipping_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録は発信機が記す — 配送印の自署を問え。

### Security — D476: `X-Twilio-*`/`X-Sinch-*`/`X-RingCentral-*`/`X-Vonage-*`/`X-Infobip-*`/`X-Webex-*` 等の通信 API・サポート印自称が未検査

- **問題**: `X-Twilio-*` (Twilio)、`X-Sinch-*` (Sinch)、`X-RingCentral-*` (RingCentral)、`X-Vonage-*`/`X-MessageBird-*`/`X-Bird-*`/`X-Plivo-*`/`X-Telnyx-*`/`X-Infobip-*`/`X-Clickatell-*`/`X-TeleSign-*`/`X-Dialpad-*`/`X-Aircall-*`/`X-Webex-*`/`X-GoToMeeting-*`/`X-Drift-*`/`X-LiveChat-*`/`X-Tidio-*` は通信機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `comms_marks` + `has_comms_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 通信印の自署を問え。


### Security — D471: `X-Revolut-*`/`X-Plaid-*`/`X-Affirm-*`/`X-Venmo-*`/`X-Robinhood-*`/`X-N26-*`/`X-Monzo-*` 等のネオバンク・フィンテック印 (第二群) 自称が未検査

- **問題**: `X-Plaid-*` (Plaid)、`X-Revolut-*` (Revolut)、`X-Affirm-*` (Affirm)、`X-N26-*`/`X-Monzo-*`/`X-SoFi-*`/`X-Robinhood-*`/`X-Venmo-*`/`X-Skrill-*`/`X-Neteller-*`/`X-Remitly-*`/`X-TrueLayer-*`/`X-Tink-*`/`X-Yodlee-*`/`X-Afterpay-*`/`X-Tabby-*`/`X-Tamara-*`/`X-Scalapay-*`/`X-Rapyd-*`/`X-MoneyGram-*`/`X-Paysend-*`/`X-Nubank-*`/`X-PicPay-*` は金融機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `fintech_marks` + `has_fintech_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 金融印の自署を問え。

### Security — D472: `X-Coinbase-*`/`X-Binance-*`/`X-Kraken-*`/`X-Ledger-*`/`X-OpenSea-*`/`X-Etherscan-*` 等の暗号資産・取引所印自称が未検査

- **問題**: `X-Coinbase-*` (Coinbase)、`X-Binance-*` (Binance)、`X-Kraken-*` (Kraken)、`X-Ledger-*`/`X-Trezor-*` (ウォレット)、`X-Bitfinex-*`/`X-Bitstamp-*`/`X-Gemini-*`/`X-OKX-*`/`X-Bybit-*`/`X-KuCoin-*`/`X-HTX-*`/`X-Huobi-*`/`X-MEXC-*`/`X-Bitget-*`/`X-Nexo-*`/`X-ConsenSys-*`/`X-CoinGecko-*`/`X-CoinMarketCap-*`/`X-Etherscan-*`/`X-OpenSea-*`/`X-Rarible-*`/`X-MagicEden-*`/`X-Alchemy-*`/`X-Infura-*`/`X-QuickNode-*`/`X-Moralis-*`/`X-Chainalysis-*`/`X-Elliptic-*`/`X-Messari-*` は暗号資産機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `crypto_marks` + `has_crypto_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 暗号資産印の自署を問え。

### Security — D473: `X-Xbox-*`/`X-Blizzard-*`/`X-Nintendo-*`/`X-Roblox-*`/`X-Steam-*`/`X-Wargaming-*` 等のゲーム・エンタメ印自称が未検査

- **問題**: `X-Xbox-*` (Xbox)、`X-Blizzard-*` (Blizzard)、`X-Nintendo-*` (Nintendo)、`X-Steam-*`/`X-Valve-*` (Valve)、`X-EpicGames-*`/`X-Riot-*`/`X-Activision-*`/`X-Ubisoft-*`/`X-Rockstar-*`/`X-PlayStation-*`/`X-Mojang-*`/`X-Roblox-*`/`X-Bungie-*`/`X-SquareEnix-*`/`X-BandaiNamco-*`/`X-Sega-*`/`X-Konami-*`/`X-Niantic-*`/`X-Supercell-*`/`X-Zynga-*`/`X-Scopely-*`/`X-Rovio-*`/`X-Unity-*`/`X-BattleNet-*`/`X-Wargaming-*`/`X-Gaijin-*`/`X-GOG-*`/`X-Itch-*`/`X-CyGames-*`/`X-GungHo-*`/`X-DeNA-*`/`X-Mobage-*`/`X-GREE-*` (日本系) はゲーム機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `gaming_marks` + `has_gaming_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — ゲーム印の自署を問え。


### Security — D468: `X-Airbnb-*`/`X-Booking-*`/`X-Uber-*`/`X-DoorDash-*`/`X-Grab-*`/`X-DiDi-*`/`X-Zomato-*` 等の旅行・運輸・フードデリバリー印自称が未検査

- **問題**: `X-Uber-*` (Uber)、`X-DoorDash-*` (DoorDash)、`X-Grab-*` (Grab)、`X-Airbnb-*`/`X-Booking-*`/`X-Expedia-*`/`X-Agoda-*` (旅行)、`X-DiDi-*`/`X-Bolt-*`/`X-Gojek-*`/`X-Lyft-*`/`X-Ola-*` (配車)、`X-Deliveroo-*`/`X-JustEat-*`/`X-Zomato-*`/`X-Swiggy-*`/`X-Rappi-*`/`X-iFood-*`/`X-Coupang-*`/`X-Grubhub-*`/`X-Instacart-*`/`X-Postmates-*`/`X-Foodpanda-*`/`X-Hotels-*`/`X-Tripadvisor-*`/`X-Kayak-*`/`X-Skyscanner-*`/`X-Priceline-*`/`X-Hopper-*`/`X-FreeNow-*`/`X-Gett-*`/`X-Cabify-*` は旅行・配車・フード機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `travel_marks` + `has_travel_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録は発信機が記す — 旅行印の自署を問え。

### Security — D469: `X-Cloudflare-*`/`X-Fastly-*`/`X-Varnish:`/`X-Sucuri-*`/`X-WPEngine-*`/`X-Pantheon-*` 等の CDN・エッジ・マネージドホスティング印自称が未検査

- **問題**: `X-Varnish:` (Varnish キャッシュ)、`X-Fastly-*` (Fastly)、`X-Sucuri-*` (Sucuri WAF)、`X-Cloudflare-*`/`X-CloudFront-*`/`X-StackPath-*`/`X-KeyCDN-*`/`X-CDN77-*`/`X-BunnyCDN-*`/`X-Limelight-*`/`X-Edgio-*`/`X-Incapsula-*`/`X-Imperva-*`/`X-WPEngine-*`/`X-Kinsta-*`/`X-Pantheon-*`/`X-Acquia-*`/`X-Flywheel-*`/`X-WPE-*` は CDN・ホスティング機の経路記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `cdn_marks` + `has_cdn_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 経路の記録は経路機が記す — CDN 印の自署を問え。

### Security — D470: `X-Patreon-*`/`X-Substack-*`/`X-Beehiiv-*`/`X-Libsyn-*`/`X-Vimeo-*`/`X-Pixiv-*` 等のメディア・クリエイター・ニュースレター印自称が未検査

- **問題**: `X-Patreon-*` (Patreon)、`X-Substack-*` (Substack)、`X-Libsyn-*` (Libsyn)、`X-Beehiiv-*`/`X-ConvertKit-*`/`X-Kit-*`/`X-Flodesk-*` (ニュースレター)、`X-Simplecast-*`/`X-Buzzsprout-*`/`X-Podbean-*`/`X-Spreaker-*` (ポッドキャスト)、`X-Vimeo-*`/`X-Flickr-*`/`X-Behance-*`/`X-Dribbble-*`/`X-ArtStation-*`/`X-VSCO-*` (メディア)、`X-Pixiv-*`/`X-Ameba-*`/`X-Seesaa-*`/`X-FC2-*` (日本系) はメディア機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `media_marks` + `has_media_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録は発信機が記す — メディア印の自署を問え。


### Security — D465: `X-Rakuten-*`/`X-Mercari-*`/`X-PayPay-*`/`X-Livedoor-*`/`X-Doorkeeper-*`/`X-AtCoder-*` 等の日本系サービス印自称が未検査

- **問題**: `X-Rakuten-*` (楽天)、`X-Mercari-*` (メルカリ)、`X-PayPay-*` (PayPay)、`X-DMM-*`/`X-Livedoor-*`/`X-Hatena-*`/`X-Cookpad-*`/`X-Recruit-*`/`X-BizReach-*`/`X-Wantedly-*`/`X-Findy-*`/`X-LAPRAS-*`/`X-Lancers-*`/`X-Coconala-*`/`X-Doorkeeper-*`/`X-Peatix-*`/`X-Kakaku-*`/`X-AtCoder-*`/`X-Paiza-*`/`X-Excite-*`/`X-Goo-*`/`X-Niconico-*`/`X-Dwango-*` は日本系サービス通知機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `jp_service_marks` + `has_jp_service_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — サービス印の自署を問え。

### Security — D466: `X-Greenhouse-*`/`X-Lever-*`/`X-BambooHR-*`/`X-ADP-*`/`X-Gusto-*`/`X-Rippling-*`/`X-Workable-*` 等の HR・採用印 (第二群) 自称が未検査

- **問題**: `X-Greenhouse-*` (Greenhouse ATS)、`X-Lever-*` (Lever)、`X-BambooHR-*`/`X-ADP-*`/`X-Gusto-*`/`X-Rippling-*`/`X-Deel-*`/`X-Paylocity-*`/`X-Paycom-*`/`X-Paychex-*`/`X-Zenefits-*`/`X-UKG-*`/`X-UltiPro-*` (人事・給与)、`X-SmartRecruiters-*`/`X-Ashby-*`/`X-Jobvite-*`/`X-Workable-*`/`X-Recruitee-*`/`X-Teamtailor-*`/`X-Personio-*`/`X-Hibob-*`/`X-CultureAmp-*`/`X-Medallia-*` は HR 機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `hr_marks` + `has_hr_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 採用印の自署を問え。

### Security — D467: `X-Shopify-*`/`X-Etsy-*`/`X-Squarespace-*`/`X-Wix-*`/`X-Magento-*`/`X-AliExpress-*`/`X-Zalando-*` 等の EC・マーケットプレイス印自称が未検査

- **問題**: `X-Shopify-*` (Shopify)、`X-Etsy-*` (Etsy)、`X-Squarespace-*`/`X-Wix-*`/`X-Weebly-*`/`X-Webflow-*`/`X-BigCommerce-*`/`X-Magento-*`/`X-WooCommerce-*`/`X-PrestaShop-*`/`X-OpenCart-*`/`X-Ecwid-*`/`X-AliExpress-*`/`X-Temu-*`/`X-SHEIN-*`/`X-Allegro-*`/`X-Bol-*`/`X-Cdiscount-*`/`X-ManoMano-*`/`X-Zalando-*`/`X-Otto-*`/`X-ASOS-*`/`X-Farfetch-*`/`X-Poshmark-*`/`X-Depop-*`/`X-Vinted-*`/`X-StockX-*`/`X-Grailed-*`/`X-ThredUp-*`/`X-Vestiaire-*` は EC 機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `ecommerce_marks` + `has_ecommerce_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録は発信機が記す — EC 印の自署を問え。


### Security — D462: `X-Hetzner-*`/`X-Scaleway-*`/`X-Linode-*`/`X-Vultr-*`/`X-DigitalOcean-*`/`X-Heroku-*`/`X-Railway-*` 等のクラウド・ホスティング印自称が未検査

- **問題**: `X-Hetzner-*` (Hetzner)、`X-Scaleway-*` (Scaleway)、`X-Linode-*`/`X-Akamai-*`/`X-Vultr-*`/`X-Oracle-*`/`X-IBM-*`/`X-DigitalOcean-*`/`X-Heroku-*`/`X-Render-*`/`X-Fly-*`/`X-Railway-*`/`X-OpenShift-*`/`X-CloudFoundry-*` はクラウド機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `cloud_host_marks` + `has_cloud_host_marks` 追加; `commands.rs` で render_risks 兆候報告。`X-OVH-*` は別ブランチで扱うため対象外。
- **教訓**: 発信の記録は発信機が記す — クラウド印の自署を問え。

### Security — D463: `X-PagerDuty-*`/`X-Datadog-*`/`X-NewRelic-*`/`X-Bugsnag-*`/`X-Rollbar-*`/`X-Grafana-*`/`X-Pingdom-*` 等の監視・インシデント・分析印自称が未検査

- **問題**: `X-PagerDuty-*` (PagerDuty)、`X-Datadog-*` (Datadog)、`X-Bugsnag-*`/`X-Honeybadger-*`/`X-Rollbar-*`/`X-Airbrake-*`/`X-Raygun-*`/`X-GlitchTip-*` (エラー監視)、`X-Pingdom-*`/`X-UptimeRobot-*`/`X-StatusCake-*`/`X-Opsgenie-*`/`X-VictorOps-*`/`X-iLert-*`/`X-AlertOps-*`/`X-SIGNL4-*`/`X-NewRelic-*`/`X-Dynatrace-*`/`X-AppDynamics-*`/`X-Splunk-*`/`X-SumoLogic-*`/`X-Logz-*`/`X-Loggly-*`/`X-Papertrail-*`/`X-Sematext-*`/`X-Honeycomb-*`/`X-Lightstep-*`/`X-Grafana-*`/`X-LogRocket-*`/`X-Mixpanel-*`/`X-Amplitude-*` は監視機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `observability_marks` + `has_observability_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 監視印の自署を問え。

### Security — D464: `X-Asana-*`/`X-Monday-*`/`X-Trello-*`/`X-Basecamp-*`/`X-Miro-*`/`X-Typeform-*`/`X-JotForm-*`/`X-Qualtrics-*` 等の生産性・フォームサービス印自称が未検査

- **問題**: `X-Asana-*` (Asana)、`X-Monday-*` (Monday.com)、`X-Typeform-*`/`X-JotForm-*`/`X-Qualtrics-*`/`X-SurveyMonkey-*`/`X-SMG-*`/`X-Formstack-*`/`X-Wufoo-*` (フォーム)、`X-Trello-*`/`X-ClickUp-*`/`X-Basecamp-*`/`X-Wrike-*`/`X-Smartsheet-*`/`X-Teamwork-*`/`X-Todoist-*`/`X-Evernote-*`/`X-Coda-*`/`X-Miro-*`/`X-Mural-*`/`X-Whimsical-*`/`X-Lucid-*`/`X-Lucidchart-*`/`X-Canva-*` はサービス通知機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `productivity_marks` + `has_productivity_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — サービス印の自署を問え。


### Security — D459: `X-Facebook-*`/`X-Twitter-*`/`X-LinkedIn-*`/`X-Instagram-*`/`X-Discord-*`/`X-Spotify-*`/`X-Meetup-*` 等の SNS・プラットフォーム通知印自称が未検査

- **問題**: `X-Facebook-Notify` (Facebook 通知メール — 実測)、`X-Twitter-*`/`X-LinkedIn-*`/`X-Instagram-*`/`X-YouTube-*`/`X-Pinterest-*`/`X-Reddit-*`/`X-Tumblr-*`/`X-Discord-*`/`X-Twitch-*`/`X-Spotify-*`/`X-Medium-*`/`X-Quora-*`/`X-ProductHunt-*`/`X-TikTok-*`/`X-Snapchat-*`/`X-VK-*`/`X-LINE-*`/`X-Kakao-*`/`X-Weibo-*`/`X-Xing-*`/`X-Meetup-*`/`X-Eventbrite-*` は SNS 通知機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `sns_platform_marks` + `has_sns_platform_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — SNS 印の自署を問え。

### Security — D460: `X-Square-*`/`X-Adyen-*`/`X-Klarna-*`/`X-Wise-*`/`X-Razorpay-*`/`X-Alipay-*`/`X-Mollie-*`/`X-Paddle-*` 等の決済・金融サービス印自称が未検査

- **問題**: `X-Square-*` (Square)、`X-Adyen-*` (Adyen)、`X-Razorpay-*` (Razorpay)、`X-Braintree-*`/`X-Worldpay-*`/`X-Klarna-*`/`X-Wise-*`/`X-TransferWise-*`/`X-Authorize-*`/`X-AuthNet-*`/`X-Recurly-*`/`X-Chargebee-*`/`X-Zuora-*`/`X-Paddle-*`/`X-FastSpring-*`/`X-Gumroad-*`/`X-Paytm-*`/`X-PayU-*`/`X-MercadoPago-*`/`X-PagSeguro-*`/`X-EBANX-*`/`X-Payoneer-*`/`X-Alipay-*`/`X-UnionPay-*`/`X-Mollie-*` は決済機の発信記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `payment_marks` + `has_payment_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 決済の記録は決済機が記す — 決済印の自署を問え。

### Security — D461: `X-PHPlist-*`/`X-Sendy-*`/`X-MailWizz-*`/`X-Mautic-*`/`X-MoEngage-*`/`X-OneSignal-*`/`X-Urban-*`/`X-Netcore-*` 等の配信 ESP・マーケ印 (第四群) 自称が未検査

- **問題**: `X-MoEngage-*` (MoEngage)、`X-Urban-*` (Urban Airship)、`X-Netcore-*` (Netcore)、`X-PHPlist-*`/`X-Sendy-*`/`X-MailWizz-*`/`X-OpenEMM-*`/`X-Agnitas-*`/`X-Mautic-*`/`X-Emma-*`/`X-JangoMail-*`/`X-WhatCounts-*`/`X-StrongView-*`/`X-WebEngage-*`/`X-CleverTap-*`/`X-OneSignal-*`/`X-Airship-*`/`X-Attentive-*`/`X-Emarsys-*`/`X-Selligent-*`/`X-Dotdigital-*`/`X-Bloomreach-*`/`X-Cordial-*`/`X-Blueshift-*` は配信機の記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `esp4_marks` + `has_esp4_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配信の記録は配信機が記す — ESP 印の自署を問え。


### Security — D456: `X-Bugzilla-*`/`X-Phabricator-*`/`X-Discourse-*`/`X-YouTrack-*`/`X-MediaWiki-*`/`X-phpBB-*`/`X-XenForo-*`/`X-Redmine-*` 等のフォーラム・課題管理印自称が未検査

- **問題**: `X-Bugzilla-Reason`/`X-Bugzilla-Type` (Bugzilla 通知 — 公式文書)、`X-Discourse-Topic-Id`/`X-Discourse-*` (Discourse)、`X-YouTrack-*`/`X-Phabricator-*`/`X-Phorge-*`/`X-MediaWiki-*`/`X-Redmine-*`/`X-Mantis-*`/`X-Trac-*`/`X-phpBB-*`/`X-XenForo-*`/`X-Invision-*`/`X-vBulletin-*`/`X-Flarum-*`/`X-SMF-*`/`X-MyBB-*`/`X-NodeBB-*`/`X-Drupal-*`/`X-Joomla-*`/`X-Moodle-*` はフォーラム・課題機の通知記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `forum_issue_marks` + `has_forum_issue_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — フォーラム・課題印の自署を問え。

### Security — D457: `X-GlobalRelay-*`/`X-Smarsh-*`/`X-ZL-*`/`X-Mimosa-*`/`X-Jatheon-*`/`X-ArcTitan-*`/`X-MailStore-*`/`X-Cryoserver-*`/`X-CommVault-*`/`X-Veritas-*` 等のアーカイブ・コンプライアンス印自称が未検査

- **問題**: `X-GlobalRelay-*` (Global Relay 記録保持)、`X-MailStore-*` (MailStore Server)、`X-Smarsh-*`/`X-ZL-*`/`X-ZLTech-*`/`X-Mimosa-*`/`X-Jatheon-*`/`X-ArcTitan-*`/`X-Cryoserver-*`/`X-CommVault-*`/`X-Veritas-*`/`X-EVault-*`/`X-MetaLogix-*`/`X-SourceOne-*`/`X-ES1-*` はアーカイブ機の記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `archive_marks` + `has_archive_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 保管の記録は保管機が記す — アーカイブ印の自署を問え。

### Security — D458: `X-Sangfor-*`/`X-NSFOCUS-*`/`X-TopSec-*`/`X-Hillstone-*`/`X-Venustech-*`/`X-Huawei-*`/`X-Rising-*`/`X-Antiy-*`/`X-Kingsoft-*` 等の中国系セキュリティ製品印自称が未検査

- **問題**: `X-Sangfor-*` (Sangfor)、`X-NSFOCUS-*` (緑盟科技)、`X-Rising-*` (瑞星)、`X-Antiy-*` (安天)、`X-TopSec-*`/`X-Hillstone-*`/`X-Venustech-*`/`X-Huawei-*`/`X-H3C-*`/`X-LeadSec-*`/`X-Qihoo-*`/`X-Qianxin-*`/`X-Jiangmin-*`/`X-Kingsoft-*`/`X-DBAppSecurity-*`/`X-DPTech-*` は製品の検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `cn_sec_marks` + `has_cn_sec_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検査の記録は検査機が記す — 製品印の自署を問え。


### Security — D453: `X-Arcor-*`/`X-Strato-*`/`X-IONOS-*`/`X-Ziggo-*`/`X-KPN-*`/`X-Bluewin-*`/`X-Telia-*`/`X-Elisa-*`/`X-Fastweb-*` 等の欧州・豪州 ISP 印 (第二群) 自称が未検査

- **問題**: `X-Strato-*` (STRATO)、`X-Bluewin-*` (Swisscom Bluewin)、`X-Arcor-*` (Arcor/Vodafone)、`X-TalkTalk-*`/`X-Plusnet-*`/`X-Demon-*`/`X-Pipex-*`/`X-NTL-*`/`X-Chello-*`/`X-AON-*`/`X-Tele2-*`/`X-Telia-*`/`X-Bredband-*`/`X-ComHem-*`/`X-Elisa-*`/`X-DNA-*`/`X-Sonera-*`/`X-TDC-*`/`X-Altibox-*`/`X-Lyse-*`/`X-Sunrise-*`/`X-Cablecom-*`/`X-Hispeed-*`/`X-Fastweb-*`/`X-Terra-*`/`X-Claranet-*`/`X-Easynet-*`/`X-T-Online-*`/`X-TOI-*`/`X-Versatel-*`/`X-XS4ALL-*`/`X-UPC-*`/`X-Unitybox-*`/`X-O2-*`/`X-Eir-*`/`X-Magnet-*`/`X-Virgin-*`/`X-KPN-*`/`X-Ziggo-*`/`X-IONOS-*` は ISP の受信・検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `eu_isp2_marks` + `has_eu_isp2_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 受信の記録は受信機が記す — ISP 印の自署を問え。

### Security — D454: `X-Virus-Status`/`X-Virus-Found`/`X-Virus-Checked`/`X-KAV-*`/`X-Norman-*`/`X-FProt-*`/`X-Malware-*`/`X-Infected-*` 等のウイルススキャン印 (第六群) 自称が未検査

- **問題**: `X-Virus-Status:`/`X-Virus-Found:`/`X-Virus-Checked:`/`X-Virus-Report:`/`X-Virus-Alert:` (amavisd-new/clamav-milter 実測)、`X-KAV-*` (Kaspersky AV)、`X-Norman-*`/`X-FProt-*`/`X-ESAV-*`/`X-VBA32-*`/`X-Webroot-*`/`X-Emsisoft-*`/`X-QuickHeal-*`/`X-eScan-*`/`X-SecureAge-*`/`X-VScan-*`/`X-ScanMail-*`/`X-ClamAV-*`/`X-Antivir-*`/`X-AV-Check`/`X-AV-Scan`/`X-Mfilter-*`/`X-Infected-*`/`X-Malware-*`/`X-Trojan-*` はスキャン機の検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `virus_scan_marks` + `has_virus_scan_marks` 追加; `commands.rs` で render_risks 兆候報告。`X-Virus-Scanned:` は別ブランチでカバー済みのため対象外。
- **教訓**: 検査の記録は検査機が記す — ウイルススキャン印の自署を問え。

### Security — D455: `X-Valimail-*`/`X-dmarcian-*`/`X-EasyDMARC-*`/`X-OnDMARC-*`/`X-PhishMe-*`/`X-Cofense-*`/`X-GoPhish-*`/`X-PhishLabs-*` 等の DMARC 運用・フィッシング評価印自称が未検査

- **問題**: `X-Valimail-*` (Valimail)、`X-dmarcian-*` (dmarcian)、`X-EasyDMARC-*`/`X-OnDMARC-*`/`X-RedSift-*`/`X-Fraudmarc-*`/`X-DMARCAnalyzer-*` (DMARC 運用サービス)、`X-PhishMe-*`/`X-Cofense-*` (Cofense/PhishMe 訓練)、`X-GoPhish-*` (GoPhish OSS)、`X-Lucy-*`/`X-Wombat-*`/`X-PhishLabs-*`/`X-PhishTank-*`/`X-OpenPhish-*`/`X-Abnormal-*` は評価・運用機の記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `phish_eval_marks` + `has_phish_eval_marks` 追加; `commands.rs` で render_risks 兆候報告。`X-DMARC-*` 印は別ブランチでカバー済みのため対象外。
- **教訓**: 評価の記録は評価機が記す — DMARC・フィッシング印の自署を問え。


### Security — D450: `X-Received-SPF:`/`X-SPF-*`/`X-SID-*`/`X-DomainKeys-*`/`X-DKIM-Result`/`X-DKIM-Check`/`X-Verify-*`/`X-Verification-*` 等の受信側認証結果印自称が未検査

- **問題**: `X-Received-SPF:`/`X-SPF-Result` (受信側 SPF 判定)、`X-SID-PRA`/`X-SID-Result` (SenderID)、`X-DomainKeys-Status` (DomainKeys)、`X-DKIM-Result`/`X-DKIM-Check`/`X-DKIMVerify`/`X-Verification-*`/`X-Verify-*` は受信機の検証記録 — 送信側が書くことは自称。`DKIM-Signature:` 自体は送信者が正規に付けるため対象外。
- **修正**: `Envelope` に `auth_result_marks` + `has_auth_result_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検証の記録は検証機が記す — 認証結果印の自署を問え。

### Security — D451: `X-AppRiver-*`/`X-MessageLabs-*`/`X-FrontBridge-*`/`X-FOPE-*`/`X-RedCondor-*`/`X-SpamArrest-*`/`X-AVG-*`/`X-AltoSpam-*` 等のセキュリティアプライアンス印 (第五群) 自称が未検査

- **問題**: `X-MessageLabs-*` (Symantec.cloud)、`X-FrontBridge-*`/`X-FOPE-*` (Microsoft FrontBridge/FOPE)、`X-AppRiver-*`/`X-RedCondor-*`/`X-SpamArrest-*`/`X-MailDistiller-*`/`X-OnlyMyEmail-*`/`X-AltoSpam-*`/`X-Cyberoam-*`/`X-AVG-*`/`X-BullGuard-*`/`X-MXHero-*`/`X-DuoCircle-*`/`X-ElectricMail-*`/`X-Perimeter-*`/`X-CrystalTech-*`/`X-MessageCast-*` は製品の検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `appliance5_marks` + `has_appliance5_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検査の記録は検査機が記す — アプライアンス印の自署を問え。

### Security — D452: `X-AuditID:`/`X-Entity-Ref-ID`/`X-ASG-Debug-ID`/`X-GBUdb-*`/`X-CT-RefID`/`X-Failed-Recipients:`/`X-NDR-*`/`X-Deferred-*` 等の追跡・監査・配信失敗印自称が未検査

- **問題**: `X-AuditID`/`X-Entity-Ref-ID`/`X-ASG-Debug-ID`/`X-GBUdb-Analysis` (レジストリ掲載)、`X-CT-RefID` (MailMarshal 参照 ID)、`X-Failed-Recipients` (Exchange/Postfix 配信失敗記録)、`X-Track-*`/`X-Trace-*`/`X-Correlation-*`/`X-Conversation-*`/`X-Thread-*`/`X-Session-*`/`X-Request-*`/`X-LibVersion:`/`X-NDR-*`/`X-Delayed-*`/`X-Deferred-*`/`X-NonDelivery-*`/`X-Undeliverable-*` は監査・追跡機の記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `tracking_marks` + `has_tracking_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 監査の記録は監査機が記す — 追跡印の自署を問え。


### Security — D447: `X-ML-*`/`X-MLName:`/`X-Mail-Count:`/`X-Mailman-*`/`X-List-*`/`X-Listserv-*`/`X-Sympa-*`/`X-Majordomo-*`/`X-eGroups-*`/`X-Topica-*` 等のリスト配信・ML 印自称が未検査

- **問題**: `X-MLName`/`X-Mail-Count`/`X-MLServer`/`X-ML-Id` (fml)、`X-Mailman-Version`/`X-Listprocessor-Version`/`X-List-Administrivia` (レジストリ掲載)、`X-eGroups-Approved-By`/`X-YahooGroup-*`/`X-Topica-*`/`X-Freelists-*`/`X-Groupsio-*`/`X-SmartList-*`/`X-Listar-*`/`X-Ecartis-*`/`X-CiviCRM-*` 等の ML・リスト配送記録は送信側が書くことは自称。
- **修正**: `Envelope` に `mailinglist_marks` + `has_mailinglist_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配送の記録は ML が記す — リスト印の自署を問え。

### Security — D448: `X-GitHub-*`/`X-GitLab-*`/`X-Gitea-*`/`X-Jenkins-*`/`X-PayPal-*`/`X-DocuSign-*`/`X-Slack-*`/`X-Stripe-*` 等の SaaS 通知印自称が未検査

- **問題**: `X-GitHub-Reason`/`X-GitHub-Sender`/`X-GitHub-Recipient`/`X-GitHub-Recipient-Address` (GitHub 公式文書)、`X-GitLab-NotificationReason`/`X-GitLab-Project` (GitLab)、`X-Gitea-*` (Gitea ソース)、`X-PayPal-*`/`X-DocuSign-*`/`X-Slack-*`/`X-Stripe-*`/`X-eBay-*`/`X-Amazon-*`/`X-Atlassian-*`/`X-Jenkins-*`/`X-Travis-*`/`X-CircleCI-*`/`X-Vercel-*`/`X-Netlify-*`/`X-Zoom-*`/`X-Notion-*`/`X-Figma-*`/`X-Calendly-*`/`X-Loom-*`/`X-Airtable-*`/`X-Dropbox-*`/`X-Box-*`/`X-Sentry-*` 等の SaaS 通知記録は送信側が書くことは自称。
- **修正**: `Envelope` に `saas_notify_marks` + `has_saas_notify_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — SaaS 印の自署を問え。

### Security — D449: `X-Postini-*`/`X-MXLogic-*`/`X-PMX-*`/`X-WatchGuard-*`/`X-CTCH-*`/`X-FireEye-*`/`X-Agari-*`/`X-Avast-*`/`X-ESET-*`/`X-Avira-*` 等のセキュリティアプライアンス印 (第四群) 自称が未検査

- **問題**: `X-Postini-Spam` (Google Postini)、`X-MXLogic-*` (MX Logic)、`X-PMX-*` (Sophos PureMessage)、`X-CTCH-*`/`X-Commtouch-*` (Cyren)、`X-WatchGuard-*`/`X-SNCR-*`/`X-SonicWall-*`/`X-SpamSoap-*`/`X-iScan-*`/`X-GMS-*`/`X-Tumbleweed-*`/`X-NetSTAR-*`/`X-FireEye-*`/`X-Agari-*`/`X-Area1-*`/`X-Avast-*`/`X-Avira-*`/`X-ESET-*`/`X-NINJA-*`/`X-MWG-*`/`X-Websense-*`/`X-Forcepoint-*`/`X-Skyhigh-*`/`X-AntiSpamEurope-*`/`X-Hornet-*` は製品の検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `appliance4_marks` + `has_appliance4_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検査の記録は検査機が記す — アプライアンス印の自署を問え。


### Security — D444: `X-Env-*`/`X-Envelope-*`/`X-MailFrom`/`X-Errors-To`/`X-Bounces-*`/`X-VERP-*`/`X-PRVS-*`/`X-Subaddress-*`/`X-Redirect-*`/`X-Forwarding-*` 等のエンベロープ配送記録印自称が未検査

- **問題**: `X-Env-From`/`X-Envelope-From`/`X-MailFrom`/`X-Errors-To`/`X-Original-Sender` (カスタムヘッダレジストリ掲載)、`X-Bounces-*`/`X-VERP-*`/`X-PRVS-*`/`X-Subaddress-*`/`X-Tag-*`/`X-NF-*`/`X-Redirect-*`/`X-Forwarding-*` は配送エージェントのエンベロープ記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `envelope_trace_marks` + `has_envelope_trace_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配送の記録は配送機が記す — エンベロープ印の自署を問え。

### Security — D445: `X-Originating-IP`/`X-Source-IP`/`X-Client-IP`/`X-Reverse-DNS*`/`X-HELO-*`/`X-EHLO-*`/`X-EIP:`/`X-IADB-*`/`X-CSA-*`/`X-Lumos-*`/`X-CAN-SPAM-*` 等の送信元 IP・認定印自称が未検査

- **問題**: `X-Originating-IP` (Sympa/Hotmail 実測)、`X-EIP:`/`X-IADB-*`/`X-CSA-*`/`X-Lumos-SenderID`/`X-CAN-SPAM-*` (カスタムヘッダレジストリ掲載 — IP 認定・評価記録)、`X-HELO-*`/`X-EHLO-*`/`X-Reverse-DNS*`/`X-Client-IP`/`X-Remote-IP`/`X-Connecting-*`/`X-Incoming-*`/`X-Relay-IP`/`X-Sending-IP` は受信機の送信元記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `source_ip_marks` + `has_source_ip_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 送信元の記録は受信機が記す — IP・認定印の自署を問え。

### Security — D446: `X-GFIME-*`/`X-SA-Exim-*`/`X-SpamExperts-*`/`X-MailMarshal*`/`X-InterScan-*`/`X-Clearswift-*`/`X-MIMEsweeper-*`/`X-Purgate-*`/`X-Esva*`/`X-MailFoundry-*`/`X-Gateprotect-*` 等の商用ゲートウェイ・フィルタ製品印 (第三群) 自称が未検査

- **問題**: `X-GFIME-*` (GFI MailEssentials)、`X-SA-Exim-*` (SA-Exim Connect-IP/RcptTo/Version)、`X-SpamExperts-*`/`X-SpamTitan-*`/`X-MMS-*`/`X-MailMarshal*`/`X-InterScan-*`/`X-ESA-*`/`X-SpamCatch-*`/`X-SpamCop-*`/`X-SpamFighter-*`/`X-SpamDetect-*`/`X-PerlMx-*`/`X-CScan-*`/`X-Purgate-*`/`X-Libra-*`/`X-Esva*`/`X-Clearswift-*`/`X-MIMEsweeper-*`/`X-MailFoundry-*`/`X-Gateprotect-*`/`X-Secpoint-*` は製品の検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `gateway_product_marks` + `has_gateway_product_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検査の記録は検査機が記す — ゲートウェイ印の自署を問え。


### Security — D441: `X-EOP*`/`X-Microsoft-Antispam:`/`X-Forefront-*`/`X-HM-*`/`X-MS-Exchange-*Loop*`/`X-MS-GCC-*`/`X-CrossPremises-*` 等の Microsoft 365/EOP/Exchange 内部印自称が未検査

- **問題**: `X-Microsoft-Antispam`/`X-Forefront-Antispam-Report` (Microsoft Learn 公式)、`X-EOPAttributedMessage`/`X-EOPTenantAttributedMessage`/`X-MS-Exchange-*-Loop`/`X-MS-Exchange-Generated-Message-Source`/`X-MS-Gcc-Journal-Report`/`X-LD-Processed` (Microsoft Exchange ループ防止公式文書) は EOP/Exchange の処理記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `ms_eop_marks` + `has_ms_eop_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配送の記録は EOP が記す — MS 内部印の自署を問え。

### Security — D442: `X-ELQ-*`/`X-Pardot-*`/`X-MC-*`/`X-Mailchimp-*`/`X-Mailjet-*`/`X-MJ-*`/`X-Mandrill-*`/`X-HubSpot-*`/`X-Report-Abuse:`/`X-Accounttype:` 等のマーケ・ESP 印 (第二群) 自称が未検査

- **問題**: `X-Mailjet-Campaign`/`X-MJ-CustomID` (Mailjet 公式ヘルプ)、`X-MC-User`/`X-Report-Abuse:`/`X-Accounttype:` (Mailchimp 実測)、`X-Mandrill-User` (Mandrill)、`X-ELQ-*`/`X-Pardot-*`/`X-Marketo*`/`X-HubSpot-*`/`X-Bronto-*`/`X-Silverpop-*`/`X-Acoustic-*`/`X-Responsys-*`/`X-ExactTarget-*`/`X-Lyris-*`/`X-Sailthru-*`/`X-Klaviyo-*`/`X-Braze-*`/`X-Iterable-*`/`X-iContact-*`/`X-AWeber-*`/`X-GetResponse-*`/`X-Intercom-*`/`X-Brevo-*` 等の配信プラットフォーム記録は送信側が書くことは自称。
- **修正**: `Envelope` に `marketing_marks` + `has_marketing_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録はプラットフォームが記す — ESP 印の自署を問え。

### Security — D443: `X-SFDC-*`/`X-ServiceNow-*`/`X-iCIMS-*`/`X-iRecruiter-*`/`X-Zendesk-*`/`X-Jira-*`/`X-SAP-*`/`X-Workday-*`/`X-Taleo-*`/`X-Kenexa-*` 等の業務・採用ツール印自称が未検査

- **問題**: `X-SFDC-User`/`X-SFDC-LK`/`X-SFDC-EntityId`/`X-SFDC-EmailCategory`/`X-SFDC-ORGTYPE` (Salesforce 公式文書)、`X-iCIMS-Priority`/`X-iCIMS-Type`/`X-iRecruiter-*`/`X-ServiceNow-*`/`X-Zendesk-*`/`X-Freshdesk-*`/`X-Jira-*`/`X-SAP-*`/`X-Workday-*`/`X-Taleo-*`/`X-Kenexa-*`/`X-BrassRing-*` 等の業務システム発信記録は送信側が書くことは自称。
- **修正**: `Envelope` に `enterprise_marks` + `has_enterprise_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 発信の記録はシステムが記す — 業務ツール印の自署を問え。


### Security — D438: `X-Gm-*`/`X-Google-*`/`X-BeenThere:`/`X-Received:`/`X-YMail-*`/`X-Yahoo-*`/`X-AOL-*`/`X-iCloud-*` 等のクラウドメール・webmail 内部印自称が未検査

- **問題**: `X-Gm-Message-State`/`X-Gm-Features`/`X-Gm-Gg` (Gmail — SpamAssassin bayes_ignore 公式一覧掲載)、`X-Google-Smtp-Source`、`X-Received:`/`X-Forwarded-Encrypted:`/`X-BeenThere:` (Google)、`X-YMail-OSG`/`X-Yahoo-Newman-Property` (Yahoo 内部配送印)、`X-AOL-Global-Disposition` (AOL 判定印 — rspamd ルールに記録) 等のクラウドメール内部記録は送信側が書くことは自称。
- **修正**: `Envelope` に `webmail_internal_marks` + `has_webmail_internal_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配送の記録はプロバイダが記す — webmail 内部印の自署を問え。

### Security — D439: `X-Status:`/`X-Keywords:`/`X-UID:`/`X-UIDL:`/`X-Seen:`/`X-Mozilla-*`/`X-IMAPbase:`/`X-Folder:` 等のメールストア・ステータス印自称が未検査

- **問題**: `X-Status:`/`X-Keywords:`/`X-UID:`/`X-UIDL:` (mbox/c-client の状態記録 — RFC 2076)、`X-Mozilla-Status*`/`X-Mozilla-Keys:` (Thunderbird mbox 互換)、`X-IMAPbase:`/`X-Folder:`/`X-Seen:`/`X-Answered:`/`X-Flagged:`/`X-Deleted:` 等のメールストア状態記録は「受信後のストアが記す」値 — 送信側が書くことは自称。
- **修正**: `Envelope` に `store_status_marks` + `has_store_status_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 状態の記録はストアが記す — ストア印の自署を問え。

### Security — D440: `X-SB*`/`X-Spambayes-*`/`X-Hammie-*`/`X-Text-Classification:`/`X-POPFile-*`/`X-Sieve-*`/`X-Filtered-*` 等のユーザー側分類ツール印自称が未検査

- **問題**: `X-SBClass`/`X-SBScore`/`X-SBRule`/`X-SBVer` (SpamBouncer 公式)、`X-Hammie-Disposition`/`X-Spambayes-Classification` (SpamBayes)、`X-Text-Classification:` (POPFile)、`X-Sieve-*`/`X-Procmail-*`/`X-Filtered-*`/`X-Milter-*`/`X-Mailfilter-*`/`X-Match:` 等の受信側分類・フィルタ記録は送信側が書くことは自称。
- **修正**: `Envelope` に `classifier_marks` + `has_classifier_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 分類の記録は分類器が記す — ローカルツール印の自署を問え。


### Security — D435: `X-Rspamd-*`/`X-Spamd-*`/`X-Stat-Signature:`/`X-Amavis-*`/`X-MailScanner-*`/`X-MIMEDefang-*` 等の OSS スキャナ・milter 印自称が未検査

- **問題**: `X-Rspamd-*`/`X-Spamd-*`/`X-Stat-Signature:`/`X-OS-Fingerprint:` (rspamd milter_headers — 公式ソース一覧)、`X-Amavis-*` (amavisd-new)、`X-MailScanner-*` (MailScanner)、`X-MIMEDefang-*`、`X-Scanned-By:` 等の OSS スキャナ印は「スキャナが記す検査記録」であり、受信 MTA が記す値を送信側が書くことは自称。
- **修正**: `Envelope` に `oss_scan_marks` + `has_oss_scan_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 検査の記録は検査機が記す — OSS スキャナ印の自署を問え。

### Security — D436: `X-DSPAM-*`/`X-Bogosity:`/`X-CRM114-*`/`X-Razor*`/`X-Pyzor-*`/`X-Greylist*`/`X-Policy-*`/`X-DNSBL-*` 等の統計・照合フィルタ印自称が未検査

- **問題**: `X-DSPAM-*` (DSPAM: X-DSPAM-Result/Signature)、`X-Bogosity:` (bogofilter)、`X-CRM114-*`、`X-Razor*`/`X-Pyzor-*` (分散照合)、`X-Greylist*` (遅延判定)、`X-Policy-*`/`X-DNSBL-*`/`X-RBL-*` (ポリシー・DNSBL) の記録は「統計機・照合機・ポリシー機が記す」値 — 送信側が書くことは自称。
- **修正**: `Envelope` に `stat_filter_marks` + `has_stat_filter_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 照合の記録は照合機が記す — 統計フィルタ印の自署を問え。

### Security — D437: `X-Postfix-*`/`X-Original-To:`/`X-Kerio-*`/`X-MDAV-*`/`X-IMSS-*`/`X-TM-AS-*`/`X-Domino-*`/`X-Zimbra-*` 等の MTA・メール製品印自称が未検査

- **問題**: `X-Original-To:` (Postfix エイリアス展開記録)、`X-MDAV-*`/`X-Spam-Processed:` (MDaemon — ベンダ文書)、`X-Kerio-*` (Kerio Connect)、`X-imss-scan-details`/`X-TM-AS-Result` (Trend Micro IMSS 公式 X-ヘッダ文書)、`X-Domino-*`/`X-Notes-*`/`X-GroupWise-*`/`X-Zimbra-*`/`X-Postfix-*`/`X-Exim-*`/`X-Qmail-*`/`X-MailEnable-*`/`X-IceWarp-*`/`X-CommuniGate-*`/`X-Scalix-*`/`X-Axigen-*`/`X-SurgeMail-*` は MTA・製品の受信・検査記録 — 送信側が書くことは自称。
- **修正**: `Envelope` に `mta_product_marks` + `has_mta_product_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 配送の記録は配送機が記す — MTA/製品印の自署を問え。


### Security — D432: `X-GMX-*`/`X-UI-*`/`UI-InboundReport:`/`X-me-*`/`X-ProXad-*` 等の欧州系 ISP 印自称が未検査

- GMX (`X-GMX-Antispam`/`X-GMX-Antivirus`、SpamAssassin 公式ルール・KMail プラグイン記載)・United Internet (`X-UI-Filterresults:`/`UI-InboundReport:`、1&1/GMX/WEB.DE 実測)・Orange/Wanadoo 系 ME プラットフォーム (`X-me-spamlevel`/`X-ME-Helo`/`X-ME-IP`、実測ヘッダ)・Free (`X-ProXad-*`) の受信判定記録は各 ISP が残す — 送信側から届くのは自称だが未検査だった
- 対処: `has_eu_provider_marks` 新設 → `Envelope.eu_provider_marks` → `render_risks` 兆候報告
- テスト +9 件

### Security — D433: `X-Mras:`/`X-Mru-*`/`X-Yandex-*`/`X-Mailru-*`/`X-Rambler-*`/`X-Naver-*`/`X-Daum-*`/`X-Hanmail-*`/`X-Nate-*`/`X-Kornet-*` 等の CIS・韓国系プロバイダ印自称が未検査

- Mail.ru Anti-Spam (MRAS) の判定記録 (`X-Mras: Ok`/`X-Mru-Authenticated-Sender`、実測ヘッダ)・Yandex (`X-Yandex-Spam`、yandex/NwSMTP 公式設定文書)・韓国系 Naver/Daum/Hanmail/Nate/Kornet の判定記録は各プロバイダが残す — 送信側から届くのは自称だが未検査だった
- 対処: `has_cis_provider_marks` 新設 → `Envelope.cis_provider_marks` → `render_risks` 兆候報告
- テスト +9 件

### Security — D434: `Auto-Submitted:`/`Precedence:`/`X-Loop:`/`X-AutoReply:`/`X-Autorespond:`/`X-Auto-Response-Suppress:`/`X-FC-Auto-Response:`/`X-MDRemoteIP:` 等の自動応答・優先度印自称が未検査

- `Auto-Submitted:` は自動応答機が応答生成時に付ける印 (RFC 3834 — 同ヘッダを含むメールへの自動応答は禁じられるため、送信側が書けば応答抑制・配送ステータス偽装に使える)、`Precedence:`/`X-Loop:` はリスト配送機の記録 (RFC 2076)、`X-MDRemoteIP:` は MailEnable の受信 IP 記録 — いずれも応答機・配送機が残す値であり送信側から届くのは自称だが未検査だった
- 対処: `has_autoreply_marks` 新設 → `Envelope.autoreply_marks` → `render_risks` 兆候報告
- テスト +9 件

### Security — D429: `X-QQ-*`/`X-Coremail-*`/`X-CM-*`/`X-Alimail-*`/`X-Sina-*` 等の中国・東アジア系プロバイダ印自称が未検査

- Tencent QQ メール (`X-QQ-SSF`/`X-QQ-mid` 等)・網易系 Coremail (`X-Coremail-Antispam`/`X-CM-TRANSID`/`X-CM-SenderInfo`、実測ヘッダ)・アリババ企業メール (`X-Alimail-AntiSpam`、Alibaba Cloud 公式文書) の検査・発信記録は各プロバイダが残す — 送信側から届くのは自称だが未検査だった
- 対処: `has_cn_provider_marks` 新設 → `Envelope.cn_provider_marks` → `render_risks` 兆候報告
- テスト +8 件

### Security — D430: `X-KSMG-*`/`X-KLMS-*`/`X-DrWeb-*`/`X-NAI-*`/`X-McAfee-*`/`X-F-Secure-*`/`X-Comodo-*`/`X-Symantec-*`/`X-GData-*`/`X-Ikarus-*` 等の AV・検査印自称 (第三群) が未検査

- Kaspersky KSMG/KLMS (公式 X-ヘッダ一覧文書)・Dr.Web (`X-DrWeb-SpamReason`、公式文書)・NAI/McAfee (`X-NAI-Spam-Score`、NCC Group 実測調査) 等の検査記録は AV ベンダのゲートウェイが残す — 送信側から届くのは自称だが未検査だった
- 対処: `has_av3_marks` 新設 → `Envelope.av3_marks` → `render_risks` 兆候報告
- テスト +9 件

### Security — D431: `X-PHP-*`/`X-Source-*`/`X-Get-Message-Sender-Via:`/`X-Authenticated-Sender:` 等のウェブスクリプト発信印自称が未検査

- `X-PHP-Originating-Script:` は PHP `mail.add_x_header` (php.net)、`X-PHP-Script:` は cPanel/Exim が nobody 実行メールへ付与、`X-Get-Message-Sender-Via:`/`X-Authenticated-Sender:`/`X-Source-*` は共有ホスティングの発信元追跡記録 — いずれも発信経路機が残す値であり送信側から届くのは自称だが未検査だった (侵害ウェブホスト経由のスパム典型印)
- 対処: `has_webscript_marks` 新設 → `Envelope.webscript_marks` → `render_risks` 兆候報告
- テスト +9 件

### Security — D426: `X-OCN-*`/`X-Biglobe-*`/`X-Nifty-*`/`X-MYASP-*`/`X-TERRACE-*`/`X-DTI-*` 等の日本 ISP・ホスティング印自称が未検査

- 国内プロバイダの受信判定記録 (`X-OCN-SPAM-CHECK`/`X-Biglobe-spamcheck`/`X-Nifty-SrcIP`/`X-DTI-Spam-Flag` 等) はプロバイダの受信基盤が残す — 送信側から届くのは「このプロバイダが判定した」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_jp_provider_marks` 新設 → `Envelope.jp_provider_marks` → `render_risks` 兆候報告
- テスト +7 件

### Security — D427: `ARC-Seal:`/`ARC-Message-Signature:`/`ARC-Authentication-Results:`/`X-ARC-*`/`BIMI-Location:`/`BIMI-Indicator:`/`BIMI-Logo-Preference:`/`X-BIMI-*` 等の受領鎖・ブランド印自称が未検査

- ARC Set は中継 ADMD が seal する受領鎖 (RFC 8617) で、BIMI-Location/BIMI-Indicator は検証後に受信 MTA が挿入するヘッダ (BIMI 仕様上送信者は設定禁止) — 送信側から届くのは「受領鎖・ブランド認証済み」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_arc_bimi_marks` 新設 → `Envelope.arc_bimi_marks` → `render_risks` 兆候報告
- テスト +8 件

### Security — D428: `Resent-From:`/`Resent-Sender:`/`Resent-To:`/`Resent-Cc:`/`Resent-Bcc:`/`Resent-Date:`/`Resent-Message-ID:` 等の再送印自称が未検査

- `Resent-*` はメッセージを輸送系に再投入した再送者が残す経路記録 (RFC 5322 §3.6.6) — 送信側から届くのは「再送経路を通った」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_resent_marks` 新設 → `Envelope.resent_marks` → `render_risks` 兆候報告
- テスト +8 件

### Security — D414: `X-MSFBL`/`X-Campaign-*`/`X-Mailing-*`/`X-Newsletter-*`/`X-Bulk-Mailer`/`X-Mailout-*` 等のバルク配信印自称が未検査

- バルク配信基盤のキャンペーン記録は基盤が残す — 送信側から届くのは「この基盤から発送した」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_bulk_marks` 新設 → `Envelope.bulk_marks` → `render_risks` 兆候報告
- テスト +7 件

### Security — D415: `X-SmartFilter-*`/`X-ClearMail-*`/`X-NetQ-*`/`X-Intego-*`/`X-MailControl-*`/`X-SecLil-*` 等のフィルタ印自称 (第四群) が未検査

- ニッチなフィルタ機の記録は機器が残す — 送信側から届くのは「このフィルタを通った」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_filter4_marks` 新設 → `Envelope.filter4_marks` → `render_risks` 兆候報告
- テスト +7 件

### Security — D416: `X-Prev-*`/`X-Next-*`/`X-Continuation-*`/`X-Fragment-*`/`X-Partial-*`/`X-Segment-*` 等の断片・継続印自称が未検査

- 断片化・分割の記録は分割機・再構築機が残す — 送信側から届くのは「断片を積んだ」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_frag_marks` 新設 → `Envelope.frag_marks` → `render_risks` 兆候報告
- テスト +7 件

### Security — D408: `X-Barracuda-*`/`X-Fortimail-*`/`X-Securence-*`/`X-MailRoute-*`/`X-Abaca-*` 等のアプライアンス印自称 (第三群) が未検査

- 商用メール機器のブランド印は機器が記す — 送信側から届くのは「この機器を通った」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_appliance3_marks` 新設 → `Envelope.appliance3_marks` → `render_risks` 兆候報告
- テスト +6 件

### Security — D409: `X-Final-Recipient:`/`X-Intended-Recipient:`/`X-Orig-Rcpt-*`/`X-MDRcpt-*`/`X-Rcpt-Info:`/`X-Final-To:` 等の最終宛先記録印自称が未検査

- 最終宛先の記録は配送機・DSN 機が残す — 送信側から届くのは「届いた宛先は記録済み」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_finalrcpt_marks` 新設 → `Envelope.finalrcpt_marks` → `render_risks` 兆候報告
- テスト +6 件

### Security — D410: `X-Hash-*`/`X-Checksum-*`/`X-MD5-*`/`X-SHA1-*`/`X-SHA256-*`/`X-Digest-*` 等の整合性・ハッシュ印自称が未検査

- ハッシュ・チェックサムの記録は検査機・照合機が残す — 送信側から届くのは「照合を通った」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_hash_marks` 新設 → `Envelope.hash_marks` → `render_risks` 兆候報告
- テスト +7 件

### Security — D378: `X-SparkPost-*`/`X-MSYS-API`/`X-MailChannels-*`/`X-SMTP2GO-*`/`X-SendPulse-*`/`X-SMTPCom-*` 等の ESP 印 (第二群) 自称が未検査

- SparkPost/MailChannels/SMTP2GO 等の配信基盤が配送時に記す印 — 送信側から届くのは「この配信基盤から発送した」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_esp2_stamps` 新設 → `Envelope.esp2_stamps` → `render_risks` 兆候報告
- テスト +5 件

### Security — D379: `X-Abuse-Info:`/`X-Antiabuse:`/`X-Abuse-Contact:`/`X-Complaints-Info:`/`X-Abuse-Report:`/`X-Anti-Abuse:` 等の abuse 情報印自称が未検査

- 「監視窓口あり」の体裁 — abuse 連絡情報は正当な経路で公表するものであり、内容側が書くのは体裁だけの自称だが未検査だった
- 対処: `has_abuseinfo_marks` 新設 → `Envelope.abuseinfo_marks` → `render_risks` 兆候報告
- テスト +5 件

### Security — D380: `X-Spam-Notice:`/`X-Virus-Notice:`/`X-Message-Status:`/`X-Message-Flag:`/`X-Antispam-Result:`/`X-Bulk:`/`X-Notice:` 等の通知・状態印自称が未検査

- 判定機・受信側が状態の記録として記す値 — 送信側から届くのは「状態まで判定済み」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_notice_marks` 新設 → `Envelope.notice_marks` → `render_risks` 兆候報告
- テスト +6 件

### Security — D363: `X-Spam-Report:`/`X-Spam-Details:`/`X-Spam-Hits:`/`X-Spam-Tests:`/`X-Spam-Probability:`/`X-Spam-Rating:` 等の SA 詳細判定値自称が未検査

- SpamAssassin が判定の内訳として記す値 — 送信側から届くのは「内訳まで判定済み」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_spam_detail_marks` 新設 → `Envelope.spam_detail_marks` → `render_risks` 兆候報告
- テスト +5 件

### Security — D364: `X-DCC-*`/`X-DCC:` 等の DCC チェックサム印自称が未検査

- DCC (Distributed Checksum Clearinghouse) による一括送信検出のチェックサム印 — 送信側から届くのは「検査基盤に照会した」体裁を内容側が主張する自称だが未検査だった
- 対処: `has_dcc_marks` 新設 → `Envelope.dcc_marks` → `render_risks` 兆候報告
- テスト +4 件

### Security — D365: `X-Autogenerated*`/`X-Autoresponder:`/`X-Autoresponse-From:`/`X-Vacation:` 等の自動生成印自称が未検査

- 「自動生成である」旨の表示を送信側が書く — 自動応答宣言は `Auto-Submitted:` (D202) が正規の経路であり、非規格 X-Autogenerated 系の名乗りは体裁だけの自称だが未検査だった
- 対処: `has_autogen_marks` 新設 → `Envelope.autogen_marks` → `render_risks` 兆候報告
- テスト +5 件

### Security — D327: `Complaints-To:`/`X-Report-Abuse:` 等の abuse 報告先自称が未検査

- 本物の ESP/ISP は abuse 窓口を自社ドメインで運用し受信側が確認できる — 送信側が窓口を名乗るのは「監視されている体裁」の自署だが未検査だった
- 対処: `has_abuse_headers` 新設 → `Envelope.abuse_headers` → `render_risks` 兆候報告
- テスト +5 件

### Security — D328: `X-MS-Has-Attach:`/`X-Has-Attach:` 添付存在自称が未検査

- `X-MS-Has-Attach:` は Exchange 輸送パイプラインが MIME を走査して付ける内部印 — 送信側から届くのは「添付存在」を内容側が主張する自称 (第 2 の添付宣言、parser differential の素地) だが未検査だった
- 対処: `has_attach_claim` 新設 → `Envelope.has_attach_claim` → `render_risks` 兆候報告
- テスト +3 件

### Security — D329: `Feedback-ID:`/`X-Feedback-ID:` FBL 識別子自称が未検査

- `Feedback-ID:` は送信者が ISP の FBL (苦情フィードバックループ) に登録している印 — 「監視に応じる運用者」の体裁を自署する擬装だが未検査だった
- 対処: `has_feedback_id` 新設 → `Envelope.feedback_id` → `render_risks` 兆候報告
- テスト +3 件


### Security — D237: `href="tel:"` 電話番号リンク (コールバックフィッシング) が未検査

- `<a href="tel:+…">` リンクは「クリック不要・電話をかけさせる」誘導経路 — 国際番号・有料番号詐取や BazaCall 型コールバックフィッシング (「不正アクセスのためサポートに電話せよ」) の配送手段として観測されるが、`http(s)` のみの URL 抽出を完全に素通りしていた
- 対処: `has_tel_link` 新設で `<a href="tel:`/`'tel:` を検出 → `tel_link` → `render_risks` に兆候報告
- テスト +5 件

### Security — D238: `Content-Disposition: inline` で危険拡張子添付が未検査

- `inline` 宣言は「ユーザーに見せる」の意味 — その宣言のまま実行形式 (`filename="run.exe"` 等) を埋め込むと「見せるものが実行される」偽装になるが、宣言型と拡張子の組合せは未検査だった
- 対処: `has_inline_dangerous_attachment` 新設で生ヘッダ走査 (inline + filename 近接) → `inline_dangerous_attachment` → `render_risks` に兆候報告
- テスト +4 件

### Security — D239: 疑似署名添付 (`signature.asc`/`smime.p7s` 等) が未検査

- `signature.asc`/`signature.p7s`/`smime.p7s` 等は「署名済み」の体裁を持つ — 検証機構なしの表示では「信頼できる」に見えるため、体裁だけで信頼を獲得しつつ実行形式を内包し得る (S/MIME 偽装)。正当な署名付きメールは `multipart/signed` 型で届くため、単独添付の署名ファイルは体裁のみの偽装
- 対処: `is_pseudo_signature_attachment` 新設で `scan_attachment_bytes` の step 7 に配線
- テスト +4 件


### Security — D279: multipart 宣言なのに `boundary=` パラメータがない

- 区切りを定義しない multipart は解析不能 — 手作り生成品の兆候 (phantom boundary とは別系: 宣言自体が欠ける)
- 対処: `has_missing_boundary_param` 新設 → `Envelope.missing_boundary_param` → `render_risks` 兆候報告

### Security — D280: `Content-Type:` ヘッダの欠落が未検査

- 型を名乗らないメッセージ — 正規 MUA が必ず付ける必須系ヘッダの欠落で手作り生成品の兆候
- 対処: `has_missing_content_type` 新設 → `Envelope.missing_content_type` → `render_risks` 兆候報告

### Security — D281: `Return-Path:` が `<` を含まない不正値が未検査

- RFC 5321 は `<addr>` または空 `<>` の形 — 山括弧を欠く値は手作り生成品の兆候
- 対処: `has_malformed_return_path` 新設 → `Envelope.malformed_return_path` → `render_risks` 兆候報告

### Security — D173: URL スキーム難読化 (hxxp / バックスラッシュ / 見せかけスキーム) を検出

- 本文 URL 抽出は `http://`/`https://` 始まりのみを拾うため、フィッシングキットが使う **defanged スキーム `hxxp://`** と、ブラウザが `\` を `/` として受理する **`http:\evil.example`**・**`https:/\evil.example`** 系バックスラッシュ区切り、さらに **`httр://` (Cyrillic р U+0440)** のような見せかけスキームの 3 系統が評判判定・不一致検査の両方を素通りしていた (PhishLabs/Kaspersky 系で観測されるフィルタ回避の定形)
- 対処: `kaname_render::find_obfuscated_url_tokens` を新設し、`commands.rs` で兆候 (`render_risks`) として報告。defanged/バックスラッシュは正規化 URL として復元してリンク評価に併記、見せかけスキームは復元不能なため兆候のみ報告
- テスト +9 件 (hxxp/hxxps/defanged、\\・:\\・/\\ バックスラッシュ 3 系、Cyrillic scheme、否定、HTML 文脈、山括弧内)

### Security — D174: `List-Unsubscribe` ヘッダー内リンクがリンク評価を素通り

- ワンクリック配信解除 (`List-Unsubscribe: <https://…>`) の URL はヘッダー内のみに存在し本文には現れないため、本文 URL 抽出を起点とする評判判定・SaaS リンク評価の対象外だった — 解除リンクを装ったフィッシング先誘導 (解除要求でメアド生存確認 → 本格攻撃) は定形手口
- 対処: `Envelope::list_unsubscribe` を新設してヘッダー生値を保持し、`commands.rs` で `<…>` 内の http リンクを `urls` に併記 → `evaluate_link_risks`/`evaluate_saas_links` がそのまま評価
- テスト +2 件 (抽出確認、非存在で None)

### Security — D166: 添付の実行・コンテナ拡張子欠落と RTLO ファイル名偽装を検出

- `is_dangerous_windows_attachment` のリストに `.exe`/`.com`/`.jar` という最も基本的な直接実行形式が含まれておらず、`.exe` 添付は拡張子チェックを素通りしていた。併せて `.iso`/`.img`/`.vhd`/`.vhdx` コンテナ形式が未収録だった — コンテナ内ファイルは Mark-of-the-Web を継承しないため警告が減る MOTW bypass として 2023 年以降の主要配送経路 (Mandiant/Sekoia の Qbot・Pikabot・AgentTesla 解析で報告)
- さらにファイル名への双方向テキスト制御文字 (U+202E RTLO 等) 混入が未検査だった — `invoice\u{202E}gpj.exe` は表示が反転して「invoiceexe.jpg」のように見え、実行ファイルを安全な文書・画像に見せかける古典的な表示偽装 (RTLO 攻撃、2013 年から現在も継続観測)
- 対処: 危険拡張子リストに exe/com/jar + iso/img/vhd/vhdx を追加し、`has_bidi_override_filename` (RTLO/LRO/埋め込み/アイソレート制御の全 9 文字) を新設して `scan_attachment_bytes` の危険判定に配線 — RTLO 検出時は拡張子表示反転の旨を `risks` に報告
- 誤検出対策: zip/rar/7z 等の通常アーカイブはコンテナ形式と区別して非対象。末尾拡張子判定のため `請求書.pdf.exe` の二重拡張子偽装も捕捉
- テスト +13 件 (magic_bytes: 8 件、kaname-render 添付スキャン E2E: 5 件)

### Security — D164: 複数 From アドレス / Sender ヘッダ不整合 (parser differential なりすまし) を検出

- `env.from.first()` — 解析・表示・BEC 判定の全経路が From ヘッダの**最初の 1 アドレスだけ**を見ていたため、`From: ceo@corp.example, attacker@evil.example` のような複数 From メールで 2 番目以降の混入アドレスは誰も評価していなかった。RFC 5322 §3.6.2 は複数 From に `Sender:` を必須とするが、クライアントが表示に採用するアドレスは実装ごとに差があり (先頭/末尾/連結)、この「どの差出人として見えるかが環境依存」という差異を突く parser differential 型なりすましが知られている (Dmarcian/FlashStart 等が報告)
- 対処: `Envelope::sender` を新設し `Sender:` ヘッダをパース保持 → `kaname-ui` の `from_header_anomalies` で 3 段判定して `render_risks` に兆候報告
  - 複数 From + Sender なし → RFC 違反 (強い兆候)
  - 複数 From + Sender が From 群に不一致 → RFC 違反 (Sender は From メールボックスの 1 つであるべき)
  - 複数 From + Sender が From 群に一致 → 規定準拠だが表示パーサ差異リスクは残る (軽い兆候)
- 誤検出対策: 単一 From + Sender ドメイン不一致は「on behalf of」委任送信の正常形 (ESP 経由配信で頻出) のため報告しない。From アドレス列挙は 5 件までに制限
- テスト +8 件 (kaname-render: Sender パース 3 件、kaname-ui: 4 判定ケース + 通常メール 5 件)

### Security — D162: アンカーテキストとリンク先のドメイン不一致 (URL 偽装) を検出

- `<a href="https://evil.example">https://paypal.com/login</a>` のように、**表示されるテキストが URL 形で、そのドメインが実リンク先と異なる**リンクを一切検査していなかった — メールクライアントは href 先をあまり目立たせないため、表示側の URL 形テキストを装うだけで誤認を誘える (フィッシングの基礎手口 — APWG 各報告・Unit 42/Avanan 等の観測で頻出)
- 対処: `html_to_text` が可視 `<a>` のアンカーテキストを収集し (非表示サブツリーは除外済み)、`scheme://host`・`www.`・裸 `domain.tld[/path]` 形のドメインを抽出。`registrable_domain` (末尾 2 ラベル、co.jp/co.uk 等の 2 階層 TLD は 3 ラベル、IP リテラルは全体) 比較で不一致なら `link_mismatches` に記録 → `render_risks` に兆候を報告
- 捕捉する偽装: `https://paypal.com@evil.com/` の userinfo 攻撃、表示 `www.paypal.com`・実リンク `evil.example`、表示 `paypal.com`・実リンク IP リテラル、クリックトラッカー経由で表示 URL と別ドメインへ飛ばす構成
- 誤検出対策: 登録ドメインが同じ深いサブドメインは無視、mailto:/cid: 等の非 http スキームは比較外、非表示アンカー内の「表示 URL」は評価しない
- テスト +15 件 (基本・同ドメイン・サブドメイン・userinfo・www/裸ドメイン・非 URL テキスト・非表示アンカー・co.jp・IP・未閉タグ・Cyrillic・打切り)

### Security — D160: HTML のみメールの本文解析欠落を修正し hidden text salting を遮断

- `analyze_raw_email`/`mail_scan_folder` は解析対象を `Envelope::text_body` (text/plain パート) のみから取っていたため、**text/html のみのメールでは解析入力が空文字列になり**、BEC キーワード・Cialdini・金銭要求・DLP・OOBV・リンク評価・文体認証の全てが一切検査を通らなかった — HTML 単体メールは BEC/フィッシングで一般的であり、multipart/alternative で text/plain に無害デコイ・text/html に攻撃文を置く「パート不一致」回避も同じ穴を使っていた
- 対処: `kaname_render::html_to_text` を新設 — タグスープ走査で script/style/head 等を捨て、`display:none`・`visibility:hidden`・`font-size:0`・`opacity:0`・`mso-hide:all`・`color:transparent`・負 `text-indent`・`hidden` 属性の要素をサブツリーごと落とし、実体参照 (10進/16進数値参照の難読化含む) を復号した「ユーザーが実際に見るテキスト」を復元。`<a href>` の宛先は末尾に付加しリンク検査へ供給。解析対象を text/plain + HTML 抽出文の併合に変更 (双方があれば両方ヒット)
- hidden text salting (Cisco Talos「Too salty to handle」2025-10、2024-03〜2025-07 観測): 非表示塩 `wi<span style="display:none">QXJZ</span>re` で `wire` を分断する回避を、非表示サブツリーごと捨てることで `wire` を復元。32 字以上の非表示テキストを落とした場合は `hidden_content` を立て `render_risks` に兆候を報告
- `RawHtml::as_str` を追加 (解析用アクセサ — 表示経路は従来通り `sanitize_html` のみ)

### Removed — D157: kaname-pivot の呼出元ゼロだった信頼スコア層を削除

- `PivotHistory`・`trust_score`・`trust_score_with_bec_context` は設計上「既知チャネル加点 + BEC 複合減点」の評価層だったが外部呼出元が皆無 — 実利用は `analyze`/`is_high_risk`/`channel_name` のみ。dead 層ごと削除

### Fixed — D152: text/plain メールが HTML としてパースされリンク注入できた問題を修正

- HTML 本文が無いメールで `sanitize_html` にプレーンテキストを `RawHtml` として渡していたため、text/plain 本文中の `<a href>` がクリック可能なリンクとして描画されていた — HTML 不在時はエスケープ済み text_fallback 経路にフォールバックするよう修正

### Fixed — D154: エンコード済みリダイレクトパラメータが SaaS リンク検査を素通りしていた問題を修正

- `?next=https%3A%2F%2Fevil.com` のようなパーセントエンコード済みリダイレクト先 URL を復号せず照合していたため、正規 SaaS ドメインを装った悪意ドメインへの誘導が一度も検出されなかった — クエリ値を復号してからドメイン境界照合を行うよう修正

### Fixed — D148: MLS 復号本文が全検出器を素通りしていた問題を修正

- `analyze_raw_email` は復号後も外側の固定カバー文を採点していたため、E2E 暗号メールの内容が BEC・文体認証・DLP・OOBV・リンク評価を一切通らなかった — 復号・`subject\x00body` 分割を解析の前に移動し、解析対象本文と表示件名を内側ペイロードに差し替え (認証・差出人は外側ヘッダ由来の配送層属性として維持)
- 併せて修正: `subject\x00body` が分割されず生ペイロードが UI に表示され、件名も外側カバー「(暗号化メッセージ)」のままだった — 分割後の本文のみを復号パネルに、内側件名を表示件名に


### Security — D147: BEC LLM 経路の `&str` 入口を `Content<Untrusted>` 必須に変更

- D17 が警告した「型を迂回する最短経路」が出荷経路で現実化していた — D121 で配線された `bec_score`/`bec_score_subprocess` が生 `&str` を受け、`Content<Untrusted>` 境界を経ずに不信メール本文が LLM に到達していた
- 両入口を `&Content<Untrusted>` 要求に変更し、呼出側 (`kaname-ui::bec_llm_score`) が `Content::from_network` で provenance 付きに包む構造に — 不信データを LLM に渡すには呼出側が型レベルで「これは Untrusted」と宣言しなければコンパイルできない
- `docs/threat-model.md` §3.16 の D17 記述を実態に更新 (推論はスタブではなく出荷済み、出荷経路の I1 型境界は関数 API で実効)
- 残件: Privileged モードの sandbox プロファイルと I4 の矛盾 (同モードを spawn するコードがないため非活性)


### Removed — D146: 読み手のいないオンボーディング設定を削除

- 「通知を表示する」「匿名利用統計を送信」のトグルを削除 — システム通知の発行経路もテレメトリ送信コードも存在せず、保存先の `notifications`/`telemetry` キーはどこからも読まれなかった (write-only)。テレメトリのプライバシー説明リンク (kaname.app/privacy/telemetry) は 404 — 存在しない機能に虚偽の文脈を添えていた。`settings_save_onboarding` は `onboarding_done` のみ記録する形に簡素化
- Principles 画面の stale 注記を更新: 「MLS 未実装」のため削除していた E2E 暗号化の説明を、D1 実装済み (件名を含む `subject\x00body` ペイロードを MLS で暗号化) を反映して限定付きで復元

### Removed — D139: kaname-ai::threat_intel モジュールを削除

- 呼出元ゼロの dead 設計シーム (AiPhishingDetector・AiAccessController・ContactIntelligenceEngine・ActionExtractor、1482行) を削除 — 出荷機能 (kaname-store contacts/audit_log、kaname-bec) と重複し誤読の温床だった
- maturity.md の誤帰属を修正: 「監査ログ (HMAC-SHA256 鍵付き)」は threat_intel の主張で、出荷側は kaname-store の無鍵 SHA-256 チェーン — 正直化した

### Removed — D140: 呼出元ゼロの kaname-ai モジュール群を削除

- `rule_of_two.rs`・`tiered_risk.rs`・subprocess の `PrivilegedLlmImpl`/`QuarantinedLlmImpl`/`spawn_both` を削除 (約550行) — 出荷経路は `LlmSubprocess` 直接利用のため型付きペア API は dead

### Removed — D143: kaname-crypto を定数時間比較ユーティリティに縮小

- 実暗号バックエンド不在 (D47) のまま残っていた「ML-KEM-768 + X25519 PQC ハイブリッド」の trait/API 面 (AlgId・SharedSecret・Kem・combine_kem_secrets・validate_x25519_output・MockKem・KAT テスト等 ~1,300行) を削除 — 唯一の利用者は kaname-oobv の `ct_eq`/`ct_eq_ascii_ci` だった。実 PQ は kaname-mls (openmls X-Wing) に存在

### Removed — D144: kaname-radar の dead 経路を削除

- ドメイン→インフラ解決 (`register_domain`/`resolve_infra`/`domain_to_infra`)、ユーザー報告 API (`report_email_malicious`/`is_email_in_reported_campaign`/`ReportImpact`/`user_reported_count`)、`with_retention`/`group_count`/`seen_email_count`/`extract_sld`/`all_domains` を削除 — いずれも呼出元ゼロまたは注入経路不在 (DNS 実装なし)。`EmailMetadata` の未読フィールドと commands.rs の `url_host` も除去。UI のキャンペーン表示を内部キーから人間可読ラベルに変換

### Removed — D145: 残クレートの zero-caller API を一括削除

- `SaasGuardError`・`PivotError` (返さないエラー enum)、`deepfake_advisory::i18n_key`、`Session::KANAME_MLS`、`BecDetector::deterministic_only`/`with_thresholds`、`Content::from_system`/`Bridge::validate_report` を削除 — saas-guard/pivot の thiserror 依存も除去

### Security — D141: BEC LLM 経路に注入スクリーニングと出力監査を配線

- kaname-ai: `bec_score`/`bec_score_subprocess` の入力に `PromptScreener` (Blocked→推論スキップ)、出力に `OutputAuditor` (不合格→0寄与) を接続 — E11 で未配線だった kaname-screen の防衛が実 LLM 経路に実効化 (いずれも安全側フォールバック)

### Security — D136: 文体プロファイルの送信者数に上限

- kaname-ui: STYLE_PROFILES がユニーク送信者数 (攻撃者制御) で無制限増大し settings テーブルにも永続化されていた → `MAX_STYLE_PROFILES = 1_000` で新規プロファイルを打ち切り
### Security — D130: MIME 入れ子メールの再帰深度に上限

- kaname-render: `extract_parts_by_media_type` の `message/rfc822` 再帰に `MAX_NESTED_DEPTH = 16` — 極端に深い入れ子でスタック枯渇し得た
### Security — D1 Phase 1: 実 MLS 暗号化 (openmls)

- **`kaname-mls` の XOR モック暗号を実 openmls 0.9 に全面置換** (D1 Phase 1)
  - `encrypt_message` は `MlsGroup::create_message` による本物の MLS Application 暗号文を生成 (従来は `plaintext ^ conv_id[0]` の単一バイト XOR — 鍵空間256・鍵自体が公開情報だった)
  - `process_incoming` は `MlsMessageIn` → `StagedWelcome::new_from_welcome` / `process_message` + `merge_staged_commit` で実プロトコル処理
  - `generate_key_package` は署名付きの実 `KeyPackageIn` (TLS シリアライズ) を生成 — 受け取り側は `validate()` で署名検証
  - グループ ID = `ConversationId` を `new_with_group_id` で整合させ、両側が同一の会話 ID を導出
  - 安全番号は `group.epoch_authenticator()` (全メンバーが同一値を持つ MLS の認証子) から導出 — メールアドレス+epoch の疑似ハッシュから本物の暗号素材へ
  - `Ciphersuite::KanameHybridPqc` は `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (draft-ietf-mls-pq-ciphersuites の ML-KEM-768+X25519 ハイブリッド) にマッピング — 設計書の「PQ ciphersuite を最初から選定」要件を充足
  - `MlsMailClient::try_new` を追加 (CSPRNG 初期化失敗を Result で返す)
  - `generate_key_package` の戻り値を `Option<KeyPackage>` に変更 (生成失敗を表現可能に)
  - D122 修正: `seen_welcomes` の記録を `into_group` 成功後に移動 — 不正 Welcome によるリプレイ防止スロットの燃尽 DoS を解消
  - kaname-tests の `mls_tests` を恒真テスト (内部自前 XOR) から実 `MlsMailClient` 経路に全面書き換え — 安全番号の両側不一致を正準化で解消

### Security — D1 Phase 2: MLS 状態の SQLCipher 永続化

- **`MlsMailClient::try_new_persistent(identity, db_path, key_hex)` を追加** (D1 Phase 2)
  - `openmls_sqlite_storage` の `SqliteStorageProvider` を内蔵した独自 `KanameProvider` (libcrux 暗号 + rusqlite/SQLCipher ストレージ) に差し替え — `LibcruxProvider` は MemoryStorage 固定で永続化不能だった
  - openmls グループ状態・署名鍵ペア (秘密鍵は openmls storage 内、公開鍵をメタに保存して `SignatureKeyPair::read` で復元)・会話メタ・`seen_welcomes` リプレイ帳簿を SQLCipher ファイルに永続化 — **再起動跨ぎの Welcome リプレイ防止が実効化**
  - メタ書き込みは best-effort (暗号操作成功後の失敗は warn のみ — 操作の成功自体は維持)
  - `list_conversations()` を追加 — 再起動後の UI 復元用
  - 永続化テスト 3 本: 再起動後の暗号往復継続 / 再起動跨ぎ Welcome リプレイ拒否 / 発行済み KP の秘密鍵永続化 (38 テスト全パス)
  - 残存: `try_new_persistent` の呼出元は未配線 (Phase 4 で kaname-ui に kaname-mls 依存辺を追加して接続 — DB パス/鍵は kaname-store の history.key 方式に倣う)。KeyPackage 配送経路は Phase 3、`kp_cache` は意図的に揮発のまま

### Security — D1 Phase 4: 受信経路への MLS 配線

- **`kaname_render::extract_mls_envelopes` を新設**: multipart を再帰走査 (入れ子 `message/rfc822` を含む) し、`application/mls-envelope+cbor` パートの復号済みボディを取り出す。`Content-Disposition` を問わず全パートを検査 (インライン挿入にも対応)
- **kaname-ui が kaname-mls に接続**: `analyze_raw_email` (mail_open / mail_import_eml / mail_analyze_bytes の唯一の解析経路) がエンベロープを自動で `process_incoming` に通し、`mls_events` (Welcome 参加・メンバー変更・復号イベント) と `mls_plaintexts` (復号された本文) を `ImportedEmail` に追加。`is_mls` バッジも実エンベロープ検出で立つように
- **IPC 3 件追加** (登録33 = 呼出33 = モック33): `mls_init(email)` — `<data_dir>/kaname/mls.db` (SQLCipher、`mls.key` は history.key と同じ 0600 ファイル運用。`resolve_or_create_key` をファイル名引数に汎用化) で `try_new_persistent` を起動、`mls_status` — 初期化状態と会話数、`mls_key_package` — この端末の KeyPackage を hex で返す (相手に手渡しする運用 — 配送経路は Phase 3 未実装)
- SecurityDashboard に「MLS E2E 暗号化」カードを追加 (初期化フォーム・状態・KP 表示/コピー)。既定 ciphersuite は `KanameHybridPqc` (X-Wing = ML-KEM-768 + X25519 ハイブリッド)
- 未初期化時はエラーにせず「初期化が必要」のイベントを返す — E2E はオプトインであり未設定ユーザーのメール表示を壊さない
- kaname-ui テストで Welcome 参加 → 暗号往復の実ラウンドトリップを解析経路経由で実証
- 残存: 送信側 (Compose への `encrypt_message` 統合と KeyPackage 配送 = Phase 3、`mail_send_real` の添付非対応がブロッカー)、Safety Number セレモニー UI (Phase 5)

### Security — D1 Phase 3: KeyPackage 配送経路 + 送信側暗号化

- **JMAP 添付送信を実装** (kaname-jmap): `OutgoingAttachment` + `send_email(..., attachments)` が `multipart/mixed` RFC822 を構築 — `Email/import` は生 MIME blob をそのままアップロードするため blobId 配管は不要。ファイル名の RFC 5987 拡張パラメータ (`filename*=UTF-8''...`)、添付数 32・個別 10MB・合計 25MB 上限を実装
- **KeyPackage 往復がメール添付で完結** (`application/mls-key-package` パート): `mls_send_key_package` で送信 → 受信側は `analyze_raw_email` が `extract_mls_key_packages` で検出し `validate_key_package` (TLS デシリアライズ + openmls 署名検証) 通過分のみ `kp_cache` に自動取込。KP は公開情報のため秘匿不要、経路上の差し替え対策は安全番号照合 (Phase 5) が担う
- **IPC 4 件追加** (登録37 = 呼出37 = モック37): `mls_conversations` (会話成立済み相手の一覧 + 安全番号)、`mls_send_key_package`、`mls_start_conversation` (KP を1回限り消費 → `start_one_to_one` → Welcome エンベロープ添付送信。JMAP 未接続では KP を消費する前に失敗するよう接続確認を先行)、`mls_send_encrypted` (実件名・本文は `subject\x00body` ペイロードとしてエンベロープ内のみに封入 — 外側はプレースホルダのみでサーバ・経路に一切出ない)
- **送信共通経路 `send_mail_core` を抽出**: 送信前 DLP は実内容で評価 (`dlp_target`) — E2E 暗号化経路でも情報漏洩防止が実効化したまま (暗号文の外側で DLP を通すと本文が空に見えて素通りする欠陥を構造的に回避)
- **UI**: SecurityDashboard に KP 送信/会話開始フォーム + 会話一覧 (安全番号表示 — Phase 5 セレモニーの実体)。Compose は宛先が会話成立済みの単一相手のときのみ「🔐 MLS で暗号化して送信」チェックボックスを表示
- 受信側往復テスト: KP 添付取込 → 消費で会話開始 → 双方向暗号復号を kaname-ui テストで実証 (不正 KP がキャッシュされないことも検証)
- 残存: Phase 5 (安全番号の対面セレモニー UI — 番号表示は済、照合フローが未実装)、kaname-store `mls_conversations` テーブルとのアカウント紐付け

### Security — D1 Phase 5: 安全番号セレモニー (照合記録)

- **照合状態の永続化**: kaname-store の `mls_conversations` テーブル (設計済みシーム — `safety_number`/`safety_number_verified_at` 列は存在したが書込経路ゼロだった) に `mls_mark_verified`/`mls_verification_state` を実装 — 「この時点の番号で相手と照合した」記録を会話 ID で upsert
- **IPC `mls_mark_verified` 追加** (登録38 = 呼出38 = モック38): 現在の安全番号を記録 + `MLS_SAFETY_VERIFIED` 監査イベント (件名・宛先は書かず会話 ID のみ)
- **番号変更の検出**: `mls_conversations` が各相手に `verified`/`safety_changed` を返す — 照合記録と現在値の不一致 (鍵変更・再参加・中間者攻撃の可能性) を `safety_changed` で区別。Store 未接続時は両方 false — 検証状態を偽らない
- **UI**: SecurityDashboard の会話カードに 3 状態バッジ (⚠ 番号変更 / ✓ 照合済み / 未検証) +「相手と照合しました (記録)」ボタン (別経路確認を前提とする注記付き)。Compose の MLS 選択肢にも照合前に警告を表示
- これで D1 の 5 フェーズすべてが実装済み: 実 openmls (X-Wing) → SQLCipher 永続化 → KP 添付往復 + 暗号送信 → 受信自動処理 → 信頼確立のセレモニー記録

### Security — D121: BEC 意味解析を Q-LLM サブプロセス経由に (I1 の実効化)

- kaname-ui の LLM スロットをインプロセス `LocalLlmRunner` から `Arc<LlmSubprocess>` に置き換え — 不信メール本文は `kaname-llm-runner` ワーカー (sandbox-exec `deny network*` / seccomp) に送られ、ホストプロセスの llama.cpp に入らない。ワーカー死亡・タイムアウト・スキーマ違反はすべて LLM 寄与 0 の安全側フォールバック
- `bec_score_subprocess` (kaname-ai) 追加 — `bec_score` と同じ切詰め・パース・フォールバックを共有。`LlmSubprocess::healthcheck` でモデルロード失敗の即終了を起動時に検出。モデル未配置時に spawn がモックプロセスに落ちる経路を `check_model` Ready ゲートで抑止
- 実行ファイル隣接 → PATH の順でワーカーを解決。**配布物への同梱は未設定** — `externalBin` はバイナリ不在でビルドを失敗させるため登録見送り; リリース時に `src-tauri/binaries/kaname-llm-runner-<triple>` 配置 + `externalBin` 有効化が必要

### Fixed — D126: MLS パート数の上限 (1通あたりの暗号演算 DoS)

- kaname-render: `extract_parts_by_media_type` に `MAX_MATCHING_PARTS = 32` を追加 — 無制限だと 1 通のメールに詰めた MLS エンベロープ/KeyPackage パートがそれぞれ `process_incoming` (into_group 実暗号処理) / `validate_key_package` (署名検証) を無制限に呼べ、かつ `mls_slot` Mutex が全 MLS 操作をブロックした

### Fixed — D127: ContactIntelligenceEngine の無制限コレクション

- kaname-ai `threat_intel`: `MAX_CONTACTS = 10_000` を追加 (偽装 From フラッドで contacts マップが無制限に膨張するのを抑制) + `response_times`/`send_hours` を VecDeque 化して `interaction_unix_times` と同じ 10_000 上限を適用 (片方だけの上限ではもう片方が無制限だった)
- 注記: 本モジュールは現在呼び出し元ゼロ (未配線) — 接続時は送信者数のスロットリングも検討

### Security — D128: LLM サブプロセスの未適用サンドボックスをフェイルクローズ化

- kaname-ai: Linux の seccomp 分離と Windows の Job Object 制限は**コメント上の主張のみで実装が存在しなかった** (runner は `--seccomp` を無視、プロファイル JSON も不存在) — `SandboxUnavailable` を新設し両 OS で spawn をフェイルクローズに変更。不信本文を無分離で処理するより「利用不可」が正しい。macOS の sandbox-exec は実適用を確認済み

### Added — D9 Phase 2 (部分): SSA 検出面の敵対的実測ハーネス

- kaname-ssa に `calibration_tests` モジュール追加 — 「プロファイルを完全に知る攻撃者が各軸を最大乖離させる」31 軸サブセットを列挙し、閾値 0.40/0.60/0.75 の実際の検出面を回帰ガードとして固定
- **実測された検出面**: 1 軸のみの最大乖離は警告にすら届かない (最大 0.25 — 「文体を完璧に真似たが深夜送信」は素通し)、2 軸は Low まで、最強 3 軸で Medium、全軸で High。誤検知面は健全 (正当なばらつき ±20% で警告なし)
- **発見**: `paragraphs`/`sentences_per_paragraph`/`signature_lines` は抽出されるが `style_distance` に一切寄与しないデッド次元 — 攻撃者が自由に変えられる次元 (design-d9 に記録)

### Added
- **監査証跡の閲覧経路**: `Store::audit_entries` + `security_audit_log` コマンドを追加し、SecurityDashboard に「監査証跡」セクションを実装 — append-only + ハッシュチェーンで保護された `audit_log` が書き込み専用だったのを、実データ閲覧 + チェーン検証ステータス表示可能にした

- **送信前 DLP 警告の表示**: `mail_dlp_precheck` コマンドを追加し Compose が送信クリック時に Warn 所見 (機密マーカー・大容量等) を確認 UI で表示 — 従来 `mail_send` は Block のみ止めて Warn をサイレント破棄しており警告が利用者に届かなかった

- **作成画面の送信前アドバイザリに `oobv_recommend` を配線** (D24 残件 — 台帳記載の想定用途どおり)
  - 本文入力の debounce が「DLP 事前チェック」を意図しながら空のスタブだったため実装に置き換え。送金要求・急迫表現等の別経路確認推奨文脈を送信前に助言表示 (ブロックではなく助言。呼び出し失敗は送信を妨げない)
- **OOBV 電話確認セレモニーの UI 配線**: 📞 バナー (メール開封ビュー / .eml 解析結果) に「電話で確認を開始」ボタンを追加。`oobv_start` で6単語の合い言葉+挑戦番号を発行し、電話で相手が読み上げた単語を `oobv_verify` で照合 → Verified/Mismatch/Expired/Locked を表示。共有コンポーネント `src/ui/OobvCeremony.tsx`。登録済みコマンドの UI 未呼出は `oobv_recommend` のみとなる (#145 で配線済み)
- **static-check の invoke 引数検査が `tauri::State` 注入引数を誤検出するバグを修正**: シグネチャ内の `tauri::`/`std::`/`commands::` パスセグメントを引数名と誤認していた。`State`/`AppHandle` 等のフレームワーク注入引数を除外

- **Playwright E2E が実際に実行可能になった** (D8 解消 — #147 はコンフリクトで未マージクローズのため再適用)
  - `e2e/tauri-mock.ts`: `@tauri-apps/api` の mockIPC と同構造の `__TAURI_INTERNALS__` 注入で、Tauri ランタイムなしの `npm run dev` 上で UI 層 E2E を実現。コマンド呼び出しログ (`__KANAME_MOCK_LOG`) で invoke 引数まで検証可能
  - `north-star-demo.spec.ts` を実 UI のゴールデンパスに全面書き換え (起動初期化 / 一覧 / BEC 危険バッジ+警告バナー / 本人確認 / 検索 / 作成→mail_send / サーバ接続 / オフラインフォールバック / オンボーディングゲート)、`a11y.spec.ts` を axe-core 実測に更新
  - 全行列 (Chromium/WebKit/Firefox/Accessibility) で 62 pass / 1 skip (WebKit の Tab フォーカスは OS 既定仕様のため明示スキップ)
### Removed
- **`EmailRow.triage` と `kaname-core` クレートを削除** (D97): TS 側 `triageEmail` を Rust `TriageEngine` に集約した際、UI は仕分け値を読む箇所を持たず、行ごとに計算・シリアライズされるだけの dead 出力だった。E11 が残置根拠とした「TriageEngine のみ利用中」が消えたためクレートごと削除 (git 履歴に残る)
- **呼び出し経路の無い `tauri-plugin-shell` を src-tauri から削除** (D76)
- **Compose の未使用 `reply_to` prop を削除** (D78) — 体裁だけの返信機能だった
- **永久エラー画面の「AI生成フィッシング検出 ✓」パネルと競合比較カードの同名表記を削除/訂正** (D92) — 実在しない検出機能を正常動作と表示する虚偽 UI だった
- chore(workspace): 「全クレートで共有」の共通エラー型 `kaname-error` が利用クレートゼロのまま残存していたためクレートごと削除 — ADR は未実施の意図文書と判明 (D85)
- fix(kaname-jmap): 一覧取得で `hasAttachment` プロパティを要求・パースしていたが消費者ゼロ — プロパティとフィールドを削除 (D86)

### Fixed
- **フォルダ一括解析がサブフォルダ内の .eml を全て未走査のまま完了表示していた問題を修正 (D149)**: 再帰走査 (深度8・5,000件上限、超過分は理由付きで一覧表出) に変更 — ネストしたエクスポート構造で大半が黙って抜けていた

- **クローズ済み未マージ PR に置き去りになっていた修正群を救出** (取りこぼし第2回 — 履歴再構築により D76–D111 系の ~30 件が孤児化していた):
  - fix(kaname-store): 既読/ゴミ箱操作がローカル DB に反映されず再起動で巻き戻る欠陥を修正 — `mark_messages_read`/`mark_message_deleted` + upsert の `is_deleted=0` ガード (D77)
  - fix(kaname-store): サーバ側で消えたメールがローカルに永久残存する欠陥を修正 — `reconcile_mailbox` で tombstone 化し、一覧先頭ページの部分取得時のみ走査 (D80)
  - fix(kaname-jmap): Email/set 系応答の `notCreated`/`notUpdated`/`notDestroyed` を検査 — サーバ拒否が成功として握り潰されていた (D79)
  - fix(kaname-jmap): `downloadUrl`/`uploadUrl` のテンプレート変数を URL エンコード — アカウント ID/ blob ID にテンプレート構文文字が来ると置換が壊れ任意 URL 解釈になりえた (D82)
  - fix(kaname-jmap): セッション応答の `downloadUrl`/`uploadUrl`/`uploadUrl` オリジンを検証 — 悪意ある JMAP サーバがベアラトークンを別オリジンへ誘導する経路を閉塞 (D83)
  - fix(kaname-jmap): `max_retries` が宣言のみで一度も発火しなかった — 冪等メソッド限定のリトライを `connect`/`call`/`download_blob` に実装 (D84)
  - fix(kaname-jmap): To/From アドレスのヘッダ構文文字 (`<`/`>`/`,`/CRLF) を除去 — 宛先名の改行・カンマ注入を閉塞 (D90)
  - fix(kaname-jmap): `get_email_body` の未消費本文フェッチを除去 — `bodyValues`/`fetch*BodyValues` (最大 ~1MB/通) を要求しながら blobId 経路しか使っていなかった (D93)
  - fix(kaname-store,kaname-ui): ログのフルパス出力を葉名に落とす (D96, I5)
  - fix(kaname-ui): 添付の同名上書きを `write_unique` の別名化で防止 + OOBV セレモニーの無制限蓄積に終端追い出しと上限を実装 (D87/D88)
  - fix(kaname-ui): 履歴 DB 鍵の生成を tmp+rename アトミック化し、壊鍵時の黙殺再生成 (既存 DB が復号不能になる経路) をエラー化 — 平文 DB 検出時は「旧形式」と誘導文を返す (D89)
- fix(kaname-render,kaname-ui): `is_mls` が構造的に永遠に false だった欠陥を修正 — `kaname_render::is_mls_message()` を新設し全 MIME パートの `application/mls-envelope+cbor` を検査、EML インポート経路の `BodyDto.is_mls` に配線 (JMAP 一覧は body_structure 非所持のため判別不能=false を維持) (D116)
- fix(e2e): Tauri モックの `default:` が未登録コマンドをサイレント成功させていた偽陽性経路を閉塞 — 実 Tauri と同じくエラー化し、消滅済み `ai_detect_phishing` のモック残留を削除 (D117)
- docs(performance): performance-history.md のベンチコード不在5項目 (AI summary/MLS/SQLCipher/JMAP/sanitize — うち2項目は未実装サブシステム) を「実測」から訂正 — 再現不能な数値に警告注記 (D118)
- fix(scripts): release.sh の「CI が自動リリース」主張を手動配布指示に訂正 (D7 で CI 不在) + `--bench '*'` を `--bench core_bench` に修正 (glob 非対応でベンチが走らなかった) (D119)
- fix(kaname-ui): Store 未接続時に監査イベントを無言破棄していたのを warn 化 — DLP_BLOCK 等の証跡喪失を防止 (D120)
- fix(ci-templates): ci.yml の `--bench '*'` を `--bench core_bench` に修正 (D119 と同型の glob 無効バグ — ワークフロー復活時にベンチが走らなかった)
- docs: D2 (ローカル LLM 推論) を5フェーズの実装計画に解体 — `docs/design-d2-local-llm.md` (現行コードの構造に沿った Phase 別タスク・完了条件・リスク)
- docs: D1 (MLS グループ暗号化) を5フェーズの実装計画に解体 — `docs/design-d1-mls.md` (openmls統合/永続化/KP配送/セレモニー統合/Safety Number)
- docs: D4 (Firecracker サンドボックス) を4フェーズの実装計画に解体 — `docs/design-d4-firecracker.md` (プロセス制御/vsock/OS分岐/UI統合、実機検証は Linux 必須)
- docs: D9 (SSA 敵対的サンプル校正) の設計案を解体 — `docs/design-d9-ssa-calibration.md` (生成器→検出率測定→閾値校正、実装は D2 Phase 4 前提)
- docs: maturity.md の出荷クレート数を cargo metadata 実測で訂正 (19/23 → 17/22、非出荷5件に kaname-ai を追記) / gap-analysis の D20/D37 に「現在の環境では cargo が実行可能」の追記
  - fix(kaname-ui): 詳細解析・フォルダ一括解析にも送信者履歴を供給 — `sender_history` が `None` 固定で一覧と詳細の BEC 判定が食い違っていた (D100)
  - fix(kaname-dlp,kaname-ui): 受信側 DLP に既定ルール3件を追加 (構造的に空だった) + 誤配検出へ既知宛先ドメインを連絡先履歴から供給 (D104) — kaname-dlp 変更のため security-lead 承認要
  - fix(kaname-jmap,kaname-ui): 一覧経路に Return-Path を配線し From vs Return-Path 不一致検出を実効化 + e2e モック欠落3コマンド補完 (D106/D107)
  - fix(kaname-ui): `org_domain` 設定を接続時に永続化 — 読み取り分岐 (他ユーザーの組織ドメイン既定値) が実効化 (D109)
  - fix(kaname-ui): オンボーディング完了画面の虚偽機能表示2件を削除 (D110)
  - fix(kaname-ui): `record_received` へ件名を `topic_summary` として保存する誤信号経路を閉塞 — 「話題急変」シグナルが構造的に誤発火していた (D111)
  - fix(kaname-ui): `.eml` 解析をバイト列から直接行う `mail_analyze_bytes` を追加し、開封/インポート経路を統合
  - feat(kaname-ui): メール一覧にオフセットページネーションを実装 — `mail_fetch(mailbox_id, limit, offset)` + `query_emails_page` (D68b)
  - perf(kaname-ui): 一括経路の連絡先一覧/アカウント解決を行ごとの DB 参照から一覧1回の hoist に (D108)
  - fix(kaname-observability): PII 検知のみだった `PrivacyLayer` に実抑制層を追加 (D28 残作業)
  - fix(ci): static-check 検査9 の空転 (heredoc 実行で `__file__="<stdin>"` → repo 親 dir への誤 chdir) を修正 + corpus↔target↔bin 対応の検査10追加 (D103 再発防止/D105)
  - fix(kaname-ui): オフライン時に保存済みメールが読めない不具合 + オンボーディングのデモメールを実解析エンジンに接続
  - docs: CLAUDE.md のクレート依存グラフを設計意図の記述から実測へ修正 (D101)
- **kaname-ui の async テストが共有グローバル状態で不定失敗していた問題を修正 (D115)**: `STORE`/`JMAP_SESSION`/`STYLE_PROFILES` (OnceLock) を並行テストが共有し実行順次第で相互破壊 — 全 `#[tokio::test]` 18件を `test_serial()` ロックで直列化
- **DLP 既定ポリシーが実装済み12分類器のうち8つを有効化していなかった問題を修正 (D57)**: 米国 SSN・医療情報を Outbound `Block`、弁護士秘匿特権・案件コードネーム・IBAN・SWIFT BIC を Outbound `Warn` として既定追加 + Inbound にも同6分類器の Warn を追加 (SSN/IBAN/医療データ等が既定設定で無検査のまま送信できた)。法人番号 (公表情報) と IP アドレス (単体では機微でない) は既定化を意図的に見送り — kaname-dlp 変更のため security-lead 承認要
- **SSA 文体認証の学習がアプリ再起動で全消去されていた問題を修正 (D112)**: 送信者文体プロファイルを暗号化 DB (`settings`) に永続化 — 従来は警告に必要な 10 サンプルが再起動ごとにリセットされ、実運用では一度も発火し得なかった

- fix(kaname-bec): AiTM スコアが契約上限 0-100 を超過していた (D102) — 高リスク認証パラメータ多重・PhaaS パターン・偽ドメインが重複加点され、出荷済み fuzz コーパスの種入力 (Tycoon2FA 系 URL) で実測 130+ に到達。`score.min(100)` でクランプし doc の閾値記述 (80+ → 実装の 50+) も修正。**kaname-bec 変更のため security-lead 承認要**
- feat(fuzz): 孤立していた fuzz コーパス3件に対応ターゲットを実装 (D103) — `aitm_urls`/`calendar_phishing`/`ssa_bypass` の種ファイル群はターゲット未定義で一度も実行されていなかった。`AitmDetector::analyze` (score≤100・verdict 整合性)、`CalendarGuard::analyze` (リスク⇄レベル整合性)、`EmailStyleFeatures::extract`+`assess_self_send_anomaly` (send_hour 正規化・有限性契約) を不変条件付きで追加。実走: aitm 859k / calendar 257k / ssa 1.13M exec クラッシュゼロ
- fix(fuzz): 3ターゲット中2本がコンパイル不能だった問題を修正 (D98) — `kaname_render::mime`/`::sanitize` の消滅参照を現行 API (`parse`/`sanitize_html(&RawHtml)`) に修正し libFuzzer 実走で検証 (609k/25k/1.2M exec 全クラッシュなし)。併せてハーネス側の `onerror=` 部分一致誤検知を属性スキャナに置換。static-check.sh に fuzz import 実在照合 (検査9) を追加
- fix(kaname-jmap): 送信メッセージを RFC 5322/2047 準拠に (D94) — 非 ASCII 件名を `=?UTF-8?B?` encoded-word にエンコード、本文を base64 + `MIME-Version: 1.0`/`Content-Transfer-Encoding: base64` で送出。生 UTF-8 のままでは SMTPUTF8 非対応経路で件名文字化け・本文破壊の可能性があった。base64 本文は `.` を含まないため SMTP Smuggling 終端シーケンスの構造的起因も消去
- fix(kaname-jmap): `send_email` の `draft_id` 死んだパラメータを削除 (D95) — 唯一の呼び出し元が `None` 固定で下書き削除分岐は到達不能だった
- fix(kaname-store): 「暗号化ローカルストア」が実際には平文だった問題を修正 (D75) — workspace の rusqlite が `bundled` (素の SQLite3) で `PRAGMA key`/`cipher_*` が全て silent no-op だったため DB は平文保存されていた。`bundled-sqlcipher` へ切替し `cipher_version=4.5.3` の動作を実測確認。既知文字列非出現を固定する恒久回帰テストを追加。平文期間の既存 history.db は新ビルドで開けない (移行措置なし — プレリリースのため許容判断)
- fix(kaname-jmap): JMAP ベアラトークンを Zeroizing 保持 + Debug 出力で伏字 — 切断後もヒープに残らないように (SQLCipher 鍵と同一の取り扱い)
- fix(kaname-ui): 同名添付があるとダウンロードが常に最後の blob を取得していた — `AttachmentRef` に `size` を追加し、突き合わせを `filename::mime::size` の三つ組に変更 (D91)

- fix(kaname-ui): OOBV 検証結果を改ざん検知付きの永続監査ログに記録 — 以前は読み出し経路の無いインメモリ Vec のみでプロセス終了時に証跡が消失していた
- fix(kaname-ui): SQLCipher 鍵ファイルを生成時点から 0600 で作成 — `fs::write` + 後付け chmod の競合窓 (書き込み〜chmod 間に鍵が umask 許可で読める) と chmod 失敗の無言握り潰しを解消
- ビルドプロファイル設定の二重管理を解消 — `.cargo/config.toml` の `[profile.*]` は Cargo.toml をキー単位でオーバーライドするため値が分散していた (release/bench は完全重複、dev の `split-debuginfo` は config.toml にのみ存在)。全設定を Cargo.toml に集約
- static-check.sh の誤検出を修正 — コメント内の孤立 `"` が文字列パリティを崩し SQL 内の `strftime()`/`accounts()` を「未定義関数呼び出し」と誤報していた問題を、文字列/コメント/char を単一パスで処理する状態機械に置き換えて解消。Tauri 注入引数 (`AppHandle` 等) の裸名も除外対象に追加
- docker-compose の Rust イメージを `rust:1.82-bookworm` → `rust:bookworm` に修正 — workspace の MSRV (1.85) を下回っており `docker compose up` でビルドが失敗していた
- **BEC 警戒バッジが初回ロード以降更新されなかった**: `mail:summary_updated`/`bec:alert` の購読側だけ存在し emit 側がゼロのデッドイベントだった → `mail_fetch`/`mail_mark_read`/`mail_trash` 成功時に実集計値を emit するよう配線。`bec:alert` (開封ごとに +1 で fetch 時の集計と二重計上する誤りがあった) は削除

- **ARC 検証結果を BEC 評価に実配線**: `Authentication-Results` ヘッダの `arc=` を解析対象に追加し、kaname-bec の ARC シグナル (転送チェーン改ざん +0.35 / 正当な崩れ緩和 −0.10) が実データで発火するようにした — 従来は全3経路で `arc: None` 固定

- **ゴミ箱移動がサーバー側で実際に移動していなかった欠陥**: `Email/set` の `mailboxIds` パッチは `{trash: true}` だけだと追加のみで受信トレイから除去されない (RFC 8621 §4.6) → 現在の所属を `Email/get` で取得し全て `null` で除去するパッチに修正

- **オンボーディングが完全に無スタイルで描画されていた欠陥**: `k-*` クラス37個が CSS 未定義のまま残存 (アーカイブ移行時にスタイル定義が欠落) → ダークテーマのスタイルブロックをコンポーネント内に定義。トグル・進捗ドット・危険カード等すべて正しく描画されるようになった

- **bec-scoring-spec.md が実装と乖離**: 閾値 (0.5/0.7 → 実装 0.6/0.85)・「7 信号」→ ~14 経路・最終スコア式 (線形クリップ → ロジスティック変換) を実装に合わせて訂正

- **トレイメニューのデッドコントロール**: 「新規作成...」「セキュリティポスチャー...」は emit 先のリスナーがフロントエンドに存在せずクリックしても無反応だった → `menu:compose`/`menu:security` をビュー遷移に接続。「設定...」「Kaname について」は対応ビュー自体が存在しないためメニューから削除 (実装時に git 履歴から復元)

- **Dual-LLM 型不変条件の serde 迂回穴を閉塞** (D17 部分解消): `Content<L>` から `Serialize`/`Deserialize` derive を除去 — `serde_json::from_str::<Content<Trusted>>` で Bridge を迂回し任意テキストを Trusted 偽造できた経路と、生本文の JSON 漏洩経路を閉塞。`Content<Untrusted>::as_text()` を `pub(crate)` 化、`TopicTag` を `serde(try_from)` 化し検証迂回を封じた。kaname-ai 変更のため security-lead 承認が必要。併せて `llm_bridge` の `QuarantinedLlmImpl`/`PrivilegedLlmImpl` (subprocess 側と同名の重複で、呼び出し元・テストすら存在しない in-process 経路のデッドコード ~90行) を削除 — D3 のプロセス隔離設計に反する迂回経路を消去
- **`.eml` インポート/フォルダ一括解析の無制限ファイル読み込み**: `fs::read` がサイズ確認なしで巨大ファイルを丸ごとメモリに読み込んでいた。50MB 上限 (`MAX_EML_BYTES`) を設け、超過時は正直なエラー/失敗リスト入りに

- **Dual-LLM 型不変条件の serde 迂回穴を閉塞** (D17 部分解消): `Content<L>` から `Serialize`/`Deserialize` derive を除去 — `serde_json::from_str::<Content<Trusted>>` で Bridge を迂回し任意テキストを Trusted 偽造できた経路と、生本文の JSON 漏洩経路を閉塞。`Content<Untrusted>::as_text()` を `pub(crate)` 化、`TopicTag` を `serde(try_from)` 化し検証迂回を封じた。kaname-ai 変更のため security-lead 承認が必要。併せて `llm_bridge` の `QuarantinedLlmImpl`/`PrivilegedLlmImpl` (subprocess 側と同名の重複で、呼び出し元・テストすら存在しない in-process 経路のデッドコード ~90行) を削除 — D3 のプロセス隔離設計に反する迂回経路を消去
- **送信フォームが複数宛先を扱えなかった**: `to` を単一文字列のまま1要素配列で送信していたため「a@x, b@y」と入力すると1つの不正な宛先として送信されていた。カンマ/セミコロンで分割して実配列化 + プレースホルダに複数可を明記

- **開封済みメールが一覧で未読のまま残る UI 不整合**: `EmailDetailPanel` が `mail_mark_read` を呼んでも一覧側の `is_read` が更新されず、再取得まで太字・未読ドットが残っていた。`onRead` コールバックで mark_read 成功時に一覧の該当行をローカル既読に反映 (メールボックスの未読バッジも同時に減算)

- **サイドバーの「全サブシステム正常」が常時緑の虚偽表示だった**: BEC 警戒・オフライン状態に関係なく緑を表示していた。`mail_get_summary` の実集計と `offline` シグナルに接続し、警戒時は赤で「警戒メール N 件」、オフライン時はその旨を正直に表示。併せて表示先の無かった `serverOnline`/`unreadCount` の dead state を整理

- **BEC 評価へのスレッド文脈・DKIM 署名の実データ配線** (検出ギャップ — スレッド乗っ取り/口座差し替え/DKIM `l=` 乱用検出が本番経路で発火していなかった)
  - `kaname-render`: `Envelope` に `in_reply_to`/`references`/`dkim_signature` を追加し mail-parser から抽出
  - `kaname-jmap`: `Email/get` の properties に `messageId`/`inReplyTo`/`references`/`header:DKIM-Signature:asText` を追加
  - `kaname-store`: `NewMessage`/`messages` テーブルに `message_id`/`thread_id` を永続化し、`list_thread_messages`/`list_messages_by_message_ids` を新規追加
  - `kaname-ui`: 全3評価経路 (analyze_raw_email / mail_scan_folder / assess_listing) で `thread_context`・`past_thread_bodies`・`dkim_signature_header` を実データに接続 — 従来は全て `None`/`&[]` 固定
- **BEC 評価への連絡先・Reply-To・Return-Path 実データ配線** (検出ギャップ — 実装済み検出器が本番経路で一度も発火していなかった)
  - `kaname-render`: `Envelope` に `reply_to`/`return_path` を追加し mail-parser から抽出
  - `kaname-jmap`: `Email/get` の properties に `replyTo` を追加、`EmailListItem.reply_to` に格納
  - `kaname-store`: `list_contacts` を新規追加 (kaname-bec が期待する `"表示名" <email>` / `email` 書式、5,000 件上限)
  - `kaname-ui`: 全3評価経路 (analyze_raw_email / mail_scan_folder / assess_listing) で `known_contacts`・`reply_to`・`return_path` を実データに接続 — 従来は全て `Vec::new()`/`None` 固定
- **BEC/DLP セキュリティクレートの台帳残件を修正** (D45残/D52/D54/D56/D58/D59 — 要セキュリティリード承認)
  - D45 残: kaname-bec のキーワード照合2系統 (本文のルート変更/チャネル移行/緊急・金銭マーカー群 + `contains_high_risk_topic` 件名照合) が語間ゼロ幅挿入で回避可能 → `normalize_for_matching_spaced` 併用の二重照合化。Cialdini 説得原理スコアも両正規化の max を採用
  - D52: `kaname-dlp::edm` の SHA-256 ハッシュが先頭8バイト (u64) に切り詰められ実効誕生日境界 ~2^32 → フル 256bit ダイジェスト保持に変更 (doc comment の 2^128 主張と実装が一致)。**永続化済みフィンガープリントとの互換性はなく、再登録が必要**
  - D54: 誤送信検出 `all_internal_except_last` が宛先リスト最後尾のフリーメールしか検出しない → 位置非依存化 (社内宛先 ≥1 + 社外=フリーメールのみのスレッドで全フリーメール宛先を検出、複数混入にも対応)
  - D56: AiTM 高リスク認証パラメーター検出が URL フラグメント (`#access_token=`) を見ていなかった → `#` パターン追加 (OAuth Implicit Flow のトークン窃取手口対応)
  - D58: `DkimReplayTracker` が上限なくメモリ増殖 (正常メール受信のみで発生するリソース枯渇) → 10,000 エントリ上限 + FIFO 退避
  - D59: `apply_cross_signal_escalation` の `has_auth` が符号を見ず ARC 成功 (減点) シグナルでも複合ボーナス誤発火 → 正の寄与のみカウント
- **cargo deny が deserialize 不能だった問題を修復** — deny.toml を cargo-deny 0.18+ スキーマへ移行 (廃止キー削除、`allow-wildcard-paths`、ライセンス許可追加: Zlib/Unicode-3.0/CDLA-Permissive-2.0/AGPL-3.0-or-later)。glib unsound (RUSTSEC-2024-0429) は理由・期限付きで ignore。`cargo deny check all` が全セクション ok
- **全24クレートに `license.workspace = true` + `publish = false` 付与** — ライセンスメタデータ欠落の解消
- **E2E 実行が検出した実 a11y 欠陥を修正** (D8 関連)
  - ミュートテキスト `#5A6473` が背景に対しコントラスト 2.7–3.2:1 で WCAG AA (4.5:1) 未達 → `#8B96A5` へ全置換
  - 危険色 `#E5484D` が自身の tint 背景上で 4.15:1 → `#FF6B70` へ全置換
  - ナビ非選択テキスト `rgba(255,255,255,.3)` (2.61:1) → `.55` へ
  - `h1` 不在 (Inbox 見出しを `<h1>` 化)、ナビゲーションに `role="navigation"`、コンテンツ領域に `role="main"`、作成画面の `×` に `aria-label="閉じる"`、`prefers-reduced-motion` で全 transition を 0.01ms に短縮、`:focus-visible` のフォーカスリングをグローバル保証

### Removed
- **E2E の陳腐化した架空シナリオと未使用インフラを削除** (D8 関連)
  - 旧 `north-star-demo.spec.ts` は Smart Reply 3候補・スワイプアーカイブ・Cmd+Z 取り消し・`ai_summarize_email` HTTP 傍受など未実装 UI を前提としており実行不能だったため、実 UI のゴールデンパスで全面書き換え
  - spec が一切呼ばない `cargo run -p kaname-mockserver` の webServer エントリと Mobile Safari のスワイプ project (spec 不在) を `playwright.config.ts` から除去 — これにより `npm run test:e2e` がフロントエンドのみで実行可能に
  - `scripts/init-snapshots.sh` と `e2e/__snapshots__/` の空プレースホルダ (toHaveScreenshot spec は残っていない)
- **出荷バイナリ・ワークスペースから一度も到達不能だった4クレートを削除** (D19・D6)
  - `kaname-billing` (課金 — スコープ外、永続化未実装だった D6 も消滅)、`kaname-continuity` (デバイス間ハンドオフ — 単一デバイスで完結するスコープに不要)、`kaname-i18n` (翻訳カタログ — 正規実装は `src/i18n.ts` + `src/locales/`)、`kaname-tray` (トレイ生成 — `src-tauri` の内蔵トレイと重複)
  - ワークスペース 27→23 クレート (出荷 19、意図的除外 4: mls/sandbox/mockserver/tests)。実装は git 履歴に残り将来復元可能
- **「機能デモ」タブを削除** (D51 完全解消): `KanameAppleFeatures.tsx` (1,244 行) は偽の添付・固定返信案・架空のエクスポート完了を見せるデモ遊技場であり、正直なラベル付けでも出荷する理由が無かった。`QuickLook`/`SmartReplyBar`/`PdfExportDialog`/`UndoToast`/`AccessibleEmailRow`/`UndoRedoStack` (実利用者ゼロ) も消滅。UI 到達可能性 9/9 → 8/8、関連 vitest 7 件も対象消滅のため削除
- **フロントエンド i18n 基盤を削除** (E9、~380行): `src/i18n.ts` + `src/locales/{ja,en}.json`。`t()`/`useT()`/`setLanguage()` 等の実呼び出しが UI 内にゼロで、起動時に翻訳カタログを読むだけの空転基盤だった。UI はハードコード日本語文字列のみ。kaname-i18n クレート削除 (D19) に続きフロント側の重複実装も除去
- **呼び出し元ゼロの IPC コマンド16件を削除** (E11): 「未実装」Err を返すだけの `ai_summarize_email`/`ai_smart_reply`、汎用 KV `settings_get`/`settings_set`、エージェント監視 UI の無い arxiv 系8コマンド (`screen_user_input`/`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory` + `kaname-observability::trajectory` 262行)、解析経路に内製済みの `pivot_analyze`/`deepfake_evaluate`、`history_close`/`history_open` の IPC 登録。kaname-ui から kaname-ai/kaname-screen/kaname-pivot への依存辺も除去 (クレート自体は存続)。`oobv_*` は看板機能のため残置し UI 配線で完成させる
- **呼び出し元が存在しない JMAP 差分同期・プッシュ基盤を削除** (D48 完全解消)
  - `JmapClient::sync` (~100行)、`subscribe_push` (~65行)、`SyncResult`/`ChangesResult`/`PushNotification`、`parse_sse_event`/`find_sse_event_end`、`JmapError::PushNotSupported`、`Session.event_source_url`、`Store::update_jmap_state`、`jmap_state` テーブルと `mailboxes.jmap_state` 列、kaname-jmap の `futures-util` 依存と `reqwest stream` feature を除去 (計 ~350行)
  - `mail_fetch` の全件 `Email/query`+`Email/get` 経路は正しく機能しており、差分同期が将来必要になれば git 履歴から復元可能。D19/D51 と同じく「呼び出し元の無い基盤は配線ではなく削除」の判断
  - (#148 はコンフリクトで未マージクローズされ、スタック上の #149/#151/#152 も main に入っていなかったため再適用)
- **外部参照ゼロのモジュール・API 群を一括削除** (関数レベルデッドコード掃除、計 ~2,400行)
  - `kaname-store::login_limiter` モジュール (522行・UI/コマンド層からの呼び出し元ゼロ)、`kaname-core::app_state` (525行・外部参照ゼロ)、`kaname-render::zip_guard` + `header_sanitize` (354行)、`kaname-observability` の `Metrics`/`METRICS`/`LatencyTimer`/`TelemetryConfig`/`hash_email` (~330行)、`kaname-core::ux_features` の Screener/Snooze/ReplyLater/SendLater/SafeSummary 群 (~550行・`TriageEngine` のみ利用中のため残置)、`kaname-store` の未使用 `rekey()`/`path` フィールド
  - 反対に `Store::verify_audit_chain` はテスト専用だったが実用上意味がある改ざん検出機能のため、`history_open` で警告ログを出す配線を追加 (削除せず接続)
- **ライブクレート内のデッド機能群を第2走査で削除** (E8、計 ~1,100行)。第3走査 (バリアント/フィールドレベル) では構築経路ゼロの `AuditFinding::TaskContradiction` バリアントと `scripts/pre-commit.sh` の死んだ i18n 検証 (存在しない `src/i18n/index.ts` を参照) も除去 — 以降の層 (pub フィールド) には未使用は検出されず
  - `kaname-privacy::ZeroKnowledgeSearch` + `SearchResult`/`MatchedField`/`parse_search_query` (~215行、D40 解消 — 実際の検索は `kaname_store::search_messages` で、doc 自身が「置き換える価値なし」と記述していた未配線機能)、`kaname-saas-guard::oauth_state`/`jwt_inspect` モジュール (513行)、`kaname-radar` の `DnsResolver`/`SystemDnsResolver`/`StaticDnsResolver` (~225行)、`kaname-ssa` の `OrgStyleBaseline`/`assess_with_fallback` (~160行)
- **宣言のみで参照ゼロの依存を計 61 件削除** (E10)
  - 15 クレートの `[dependencies]` 48 件: kaname-privacy は依存ゼロに (serde/serde_json/thiserror/tokio/tracing/kaname-error 全て未使用)、kaname-core は serde のみ残して 9 件除去。kaname-oobv/pivot/radar/render/observability/ssa/saas-guard/store/jmap/error/ui/tests/mockserver の未使用依存も除去。大半は E7/E8 のコード削除に伴い不要化したもの
  - workspace ルート `Cargo.toml` の未使用宣言 10 件 (anyhow/tower/aes-gcm/ed25519-dalek/x25519-dalek/scraper/criterion/tokio-test/mockito/futures-util)、kaname-jmap/ui の未使用 dev-dep `mockito`/`tokio-test`、src-tauri の `serde`/`serde_json`、npm の `@tauri-apps/plugin-shell` (フロント未参照) も除去

### Fixed
- **`messages.to_addrs` 列が NOT NULL で存在するのに `NewMessage`/`StoredMessage` にフィールドが無く、宛先が常に `''` として消失していた欠落を修正** (D46 残件)
  - `to_addrs: Vec<String>` を両構造体に追加し JSON 配列として保存。`mail_fetch` が JMAP `Email.to[].email` を供給。旧行の `''` は「宛先不明」として空配列に倒す後方互換。回帰テスト2件追加
- **`src/ui/SecurityDashboard.tsx` の未使用 setter 3件により `npm run build`/`typecheck` が main で失敗していた出荷ブロッカーを修正** (D60)
  - `noUnusedLocals` 下で TS6133 ×3。CI 不在 (D7) のため検出が遅れていた
- **`kaname-memory-guard::normalize_for_matching` のゼロ幅文字削除が複数単語キーワードの語境界を壊す回避経路を修正** (D45・kaname-bec 残件あり)
  - ゼロ幅/フォーマット文字を単一スペースに置換する `normalize_for_matching_spaced` を新設し、`TrustScorer::score`・`kaname-oobv::OobvRecommender`・`commands.rs::has_financial` の3箇所で削除版とスペース化版の二重照合に変更。`wire​transfer` 型の単語間ゼロ幅挿入を捕捉。`kaname-bec` の2箇所はセキュリティレビュー必須クレートのため未修正(詳細: `docs/gap-analysis.md` D45)
- **`kaname-render::extract_auth_result` がプロパティ値内の `dkim=pass` 風擬似トークンを機構結果と誤認しうる構造的脆さを修正し、`AuthResultsHeader.authserv_id` を露出** (D18・部分対応)
  - `;` 区切り各部の `mechanism=result` トークンのみを機構結果として認めるパースに変更 (RFC 8601)。authserv-id の信頼リスト照合自体は組織ドメイン設定 (D44) と `mail-auth` 導入に依存するため未実施
- **DLP/BEC の `our_domain` が全5箇所で `"example.com"` 固定だった欠陥を修正 — 自組織ドメインを実ソースから解決する** (D44)
  - `kaname-jmap` の `Session` に RFC 8620 の `username` フィールドを追加し `JmapClient::account_domain()` でメールドメインを自動導出。`commands.rs` の新ヘルパー `our_domain()` が 設定 `org_domain` → 呼び出し側ヒント (`from` アドレス) → 接続中アカウント導出 → 空文字 (両検出器が安全スキップ) の順で解決。`mail_connect` は `ConnectResult.org_domain` を返し、接続画面が導出した組織ドメインを表示する (設定 UI は不要 — 導出でユーザー操作ゼロ)。一覧表示では `mail_fetch` が1回だけ解決して各行に渡す (N+1 回避)

### Security
- **kaname-saas-guard: 偽装 SaaS ドメインが警告なしで素通りしていた退行を修正** — `identify_platform` のドット境界厳格化で `evaluate()` が偽装ホスト (`notdocusign.com`、`mail.google.com.evil.com` 等) を早期 `None` 返却していた。`find_impersonated_platform` で偽装先プラットフォームとして検査継続 → `is_fake_saas_subdomain` → Suspicious、注入検出で Block 格上げのパイプラインが復活
- **フロントエンド devDependencies の既知脆弱性を全件解消 (10件→0件)** (D61 解消)
  - `postcss`/`nanoid`/`js-yaml`/`browserslist`/`brace-expansion`/`baseline-browser-mapping` を非破壊的に更新 (lockfile のみ)
  - **残り4件もメジャー更新で解消**: `vite` 5→8 (rolldown 系)、`vitest` 1→5、`jsdom` 最新化、`@types/node` ^24。rolldown で `manualChunks` のオブジェクト形式が廃止されたため `vite.config.ts` を関数形式に書き換え (チャンク分割は維持)。`npm audit` 0件を実測確認

### Fixed
- **main が `cargo check` でコンパイル不能だった一連の潜伏エラーを解消** — crates.io 遮断環境では構文チェック止まりで検出不能だった5件: kaname-dlp の借用 E0597 ×2 (尾部式を let 束縛へ)、kaname-ui の `#[instrument]` 残骸・存在しない `is_mls_envelope` 呼出・E0382 ムーブ後借用・`mail_mark_read`/`mail_trash` 未定義 (JmapClient 実装で復元 — UI は既に呼出済み)
- **初の cargo test 実走で検出されたテスト失敗2件を解消** — kaname-jmap の non-snake-case 関数名をリネーム、kaname-ui の偽データ前提テストを「未接続時 Err」契約検証に置換。全 1,290 テスト合格
- **初の clippy --all-targets 実走で検出された警告エラーを一括解消** — `.cargo/config.toml` の自己再帰 `fmt` エイリアス削除、`map().unwrap_or()`→`map_or()`、`sort_by`→`sort_by_key`、`repeat().take(n)`→`repeat_n()`、`#[cfg(test)]` モジュールへの `#[allow(clippy::unwrap_used)]` 追補 (I6 は本番コード限定の意図を維持) 等
- **Cargo.lock の破損を修復** — ワークスペース crate バージョンが 0.5.0 のまま (マニフェスト 0.7.1)、`is-wsl` の version/checksum 不一致という手編集痕跡を cargo 再生成で訂正
- **実装済みの `oobv_start`/`oobv_verify`/`pivot_analyze` 3コマンドを Tauri に配線して到達可能化** (D15 残件)
  - `main.rs` に `.manage(commands::V02AppState::new())` を追加し、3コマンドを `tauri::State<'_, Arc<V02AppState>>` ラッパー経由で `invoke_handler` に登録。これで `commands.rs` の全公開コマンドが登録済みに。呼び出す UI は依然未実装 (static-check の「UI 未呼出」WARN に移行)
- **`kaname-bec::apply_cross_signal_escalation` がリスク緩和シグナル (ARC検証成功) を認証問題と誤認し複合シグナルボーナスを誤って付与することを記録** (D59・未修正・記録のみ)
  - `has_auth` 判定が `SignalFamily::Authentication` の存在チェックのみで符号 (加点/減点) を見ていないため、正規の転送メール (ARC成功による減点シグナル) が無関係な Domain/Content シグナルと重なると誤って `+0.20`/`+0.15` の複合ボーナスを受ける。正当な転送メール・請求書督促等を誤って BEC 高リスクと誤判定しうる false positive 方向の欠陥
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D59)

### Fixed
- **`kaname-bec::dkim_check::DkimReplayTracker` がエントリを一切退避せず無制限にメモリが増加することを記録** (D58・未修正・記録のみ)
  - `(domain, signature_prefix)` を `HashMap` に記録するのみで TTL/LRU/上限のいずれも無い。DKIM 署名は1通ごとに一意なため、攻撃でなくても通常のメール受信だけでプロセス生存期間中ずっと増え続ける。長期稼働するデスクトップメールクライアントで実際に影響する実用的なリソース枯渇バグ
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D58)

### Fixed
- **`kaname-dlp` の既定ポリシーが実装済み12分類器中3つしか有効化しておらず、SSN/IBAN/医療データ等が既定設定では無検査のまま送信できることを記録** (D57・未修正・記録のみ)
  - `default_rules()` が参照するのは `JpMyNumber`/`CreditCardPan`/`SourceCode` の3分類器のみ。`Iban`/`SwiftBic`/`UsSsn`/`IpAddress`/`AttorneyClientPrivilege`/`DealCodename`/`MedicalData`/`JpCorporateNumber` の8分類器は実装・テスト済みだが、カスタムルール読み込み (`from_db()`) も未配線のため有効化する経路が製品内に存在しない
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D57)

### Fixed
- **`kaname-bec::aitm::AitmDetector` が OAuth Implicit Flow のフラグメントトークン窃取 (`#access_token=...`) を検出できないことを記録** (D56・未修正・記録のみ)
  - 高リスク認証パラメーター検出がクエリ文字列区切り (`?`/`&`) のみを見ており、フラグメント区切り (`#`) を見ていない。Tycoon2FA/Storm-1747 等の実際の AiTM フィッシングキットが使う OAuth Implicit Flow のトークン窃取パターンを取りこぼす
  - `kaname-bec` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D56)

### Fixed
- **`kaname-screen::PromptScreener::screen` の主防御 (命令上書きフレーズ検出) がゼロ幅文字による単語間境界破壊で回避されていた欠陥を修正** (D55)
  - `kaname-screen` 独自の `normalize_for_matching` (D45 の `kaname-memory-guard` 版とは別実装) がゼロ幅文字を削除する設計のため、`ignore​all​previous` のように単語区切りにゼロ幅文字を挿入すると結合され、複数単語の override フレーズ照合が成立しなくなっていた。入力スクリーニングという Dual-LLM 境界前の最初の防御層での回避だった
  - ゼロ幅文字を削除せずスペースに置換する `normalize_for_matching_spaced` を新設し、削除版・スペース化版の両方でフレーズ照合するよう修正。回帰テストを追加

### Fixed
- **`kaname-dlp::misdirected_recipient` のフリーメール混入検出が宛先リスト最後尾以外では機能しないことを記録** (D54・未修正・記録のみ)
  - `all_internal_except_last` は「最後の1件を除く全員」が社内ドメインかのみ判定するため、フリーメールが宛先の先頭・中間にある場合は位置ベースの判定条件が成立せずサイレントに見逃す。`To`/`Cc`/`Bcc` の順序保証はどこにも無く、実際に起こりうる誤送信パターン
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D54)

### Fixed
- **`kaname-screen::OutputAuditor::audit` の漏洩先検出チェックが未正規化テキストを走査し全角回避を見逃していた欠陥を修正** (D53)
  - チェック1/7 は全角 Unicode 折り返し済みの正規化テキストを走査するが、チェック2 (漏洩先メールアドレス) とチェック3 (URL漏洩) は未正規化の原文を走査しており、全角文字で書かれた漏洩先アドレス/URLはモジュール自身が防ぐはずの回避手口をすり抜けていた
  - チェック2/3 も正規化済みテキストを走査するよう統一。全角回避を検出する回帰テストを追加

### Fixed
- **`kaname-dlp::edm::hash_token` が SHA-256 を64bitに切り詰めており doc comment の暗号強度主張と食い違うことを記録** (D52・未修正・記録のみ)
  - `hash_token` はフル SHA-256 を計算後 `digest[..8]` (64bit) のみを `u64` として保存するが、doc comment は「2^128 の誕生日境界」と主張していた。実際の衝突耐性は約 2^32
  - EDM (Exact Data Matching) の衝突は無関係なトークンを機微データ一致と誤判定しうる(false positive、可用性方向)。salt によりレインボーテーブル攻撃は引き続き防がれる
  - `kaname-dlp` は CLAUDE.md のセキュリティレビュー必須クレートのため、本セッションでは修正せず記録のみ(詳細: `docs/gap-analysis.md` D52)

### Fixed
- **「機能デモ」タブ (`KanameAppleFeatures.tsx`) 内の特定の誤情報・未表示のデモ表示を訂正** (D51・部分解消)
  - `QuickLook` の「Firecracker サンドボックスで安全にプレビュー」は、ページ全体が「デモ」と明示されているとはいえ、Firecracker が no-op (D4) であることを知らないと動作中の安全機構と誤読しうる特定の誤情報だった。「デモ表示 (Firecracker 隔離は未実装 — D4)」に訂正
  - `SmartReplyBar` の「AI 返信案」、`PdfExportDialog` の「✓ エクスポート完了」も、`invoke()` を呼ばず固定文言/固定完了状態を返すことがラベル自体には現れていなかった。それぞれ「(デモ・固定文言)」「✓ デモ完了 (実ファイルは生成されません)」に訂正
  - 実際の `invoke()` 配線(D24 で `ai_smart_reply` は honest error を返す実装済み)への切り替えはタブ全体がデモ前提のため見送り

### Fixed
- **`HtmlSmugglingDetector::analyze` の4MBサイズ上限切り詰めが UTF-8 文字境界を無視しパニックしうる欠陥を修正** (D50)
  - `&html[..MAX_HTML_BYTES]` が生のバイトオフセットでスライスするため、マルチバイト文字 (日本語等) の途中を切ると `panic!("byte index is not a char boundary")` していた。OOM DoS 対策自身がクラッシュを起こす本末転倒な状態だった
  - 既存テストは全て1バイト ASCII のみで構成されており、この境界ケースを一度もテストしていなかった
  - 切り詰め位置から `is_char_boundary` を満たすまで後退させてからスライスするよう修正。日本語1文字が4MB境界をまたぐ回帰テストを追加

### Fixed
- **`JmapClient::send_email` が送信済みフォルダ未検出時に架空のメールボックス ID にフォールバックしていた欠陥を修正** (D49)
  - `role == "sent"` のメールボックスが見つからない場合、文字列リテラル `"sent"` を実在しないメールボックス ID として使っていた。`Email/import` が失敗しても「インポート ID なし」という無関係なエラーになり根本原因が分かりにくかった
  - 同一ファイル内の `trash()` と同じパターン (`role` 未検出時に `JmapError::NotFound` を明示的に返す) に統一

### Fixed
- **`JmapClient::sync` が `hasMoreChanges` (RFC 8620 §5.2) を無視し500件超の差分をサイレント欠落させる欠陥を修正** (D48)
  - `Mailbox/changes`/`Email/changes` の `hasMoreChanges` を正しくパースしていたが、この値でページングループしておらず、`sync()` を呼ぶコードが将来書かれた場合に500件を超える差分の中間部分が永久に欠落する潜在バグだった(現時点で `sync()` 自体の呼び出し元はまだ無い)
  - `hasMoreChanges` が両方 `false` になるまで内部でループするよう修正。無限ループ防止のため最大50ページで打ち切り、打ち切り時は `has_more_changes: true` を呼び出し元に残して再開可能にした

### Fixed
- **`kaname-crypto` (ハイブリッド PQC クレート) に実暗号バックエンドが存在しないことを記録** (D47・doc comment のみ訂正・ロジック変更なし)
  - クレート冒頭が「FIPS 203/204 準拠のハイブリッド量子後暗号」と主張するが、`Cargo.toml` に暗号バックエンド依存が一切無く (`x25519-dalek`/`ml-kem` 等ゼロ)、`trait Kem` の実装は `#[cfg(test)]` 内の `MockKem` のみ。`HybridX25519MlKem::new` の実呼び出しもワークスペース全体でゼロ
  - MLS 群鍵暗号化を行う `kaname-mls` (D1: XOR モック) はそもそも `kaname-crypto` に依存しておらず、D1 と D47 は別々の未実装が独立に並存している
  - `kaname-crypto` は暗号設計レビュー (CLAUDE.md) 必須のクレートのため実装は見送り、クレート自身の doc comment のみ現状に合わせて訂正した(詳細: `docs/gap-analysis.md` D47)

### Fixed
- **`Store::save_message` がフォルダ移動・送信者情報の更新を永久に反映しない欠陥を修正** (D46)
  - `ON CONFLICT (id) DO UPDATE` の SET 句に `mailbox_id`/`from_addr`/`from_name` が含まれておらず、JMAP 側でのメール移動 (Inbox→Archive 等) や再同期時の送信者情報訂正が、決定論的 `id` による冪等 UPSERT では一切反映されなかった (オフライン閲覧が旧フォルダ・旧送信者情報のまま固定される)
  - SET 句に3カラムを追加して修正。回帰テストを2件新規追加(D20 により `cargo test` 実行不可のためコンパイル・実行は未検証、目視でのロジック確認のみ)
  - `to_addrs` 列が INSERT/UPDATE いずれも `''` 固定で宛先自体が永続化されていない別課題は `NewMessage` の構造拡張が必要なため残置(D46 に記録)

### Fixed
- **`normalize_for_matching` のゼロ幅文字除去が複数単語キーワードの語境界を壊す新たな回避経路を記録** (D45・未修正・記録のみ)
  - `kaname-memory-guard::normalize_for_matching` はゼロ幅文字 (`​` 等) を削除して単語内挿入回避 (`urg​ent`) を防ぐが、`wire​transfer` のようにスペースの代わりにゼロ幅文字を挿入されると `wiretransfer` に結合され、`kaname-oobv` の複数単語キーワード (`"wire transfer"` 等) の部分一致に失敗する
  - 単語内挿入対策が単語間挿入という逆方向の新しい回避経路を開いている。影響は `kaname-oobv`/`kaname-bec`/`kaname-screen` の3クレート
  - セキュリティリード承認必須のクレートに触れる修正のため、本セッションでは実装せず記録のみに留めた(詳細: `docs/gap-analysis.md` D45)

### Fixed
- **DLP/BEC の自組織ドメイン (`our_domain`) が全箇所で `"example.com"` にハードコードされていることを記録** (D44・未修正・記録のみ)
  - `kaname_dlp::EvalCtx.our_domain`(宛先ミス検出の自己送信除外用)と `kaname_bec::AssessmentRequest.our_domain`(なりすましドメインのホモグリフ検出用)が `commands.rs` の全5箇所で文字列リテラル `"example.com"` のまま渡されており、ログイン中アカウントの実ドメインを一切反映していない
  - 影響: (1) 送信 DLP の宛先ミス検出が自社ドメイン宛メールを常に「未知の外部ドメイン」として誤検知、(2) BEC のなりすましドメイン(ホモグリフ)検出が自社ドメインを騙る攻撃ドメインを実質検出できない(見逃し方向、より深刻)
  - 根本原因: `commands.rs`/`kaname-jmap::JmapClient` のどこにも「自組織のメールドメイン」を保持する設定・永続化の仕組みが存在しない(`JmapClient` は JMAP 内部 `account_id` のみ保持)
  - 修正には設定 UI への「組織ドメイン」入力欄の追加を伴うため、このセッションでは実装せず記録のみに留めた(詳細: `docs/gap-analysis.md` D44)

### Fixed
- **Dependabot の cargo エコシステムが上限に達し新規PRを開けなくなっていることを記録** (D43・コード変更なし)
  - `open-pull-requests-limit: 10`(cargo)に対し、未マージのcargo依存PRがちょうど10件(#37〜#45, #95)存在し上限と一致。npm由来も3件(#66/#87/#94)未マージ
  - D20(`cargo build`/`cargo check`がこの環境で実行不可)により安全にマージ判断ができないため、本セッションでは意図的に未着手のまま残した

### Fixed
- **D41 の追跡監査で `BecBadge` の表示漏れを発見** (D42・軽微)
  - バックエンドの BEC 判定エラー時フォールバックは正しく `"UNKNOWN"` を返していた(`"SAFE"` と偽らない、`assess_listing` は最初から正しく実装済み)
  - フロントエンドの `BecBadge`(Inbox.tsx)がこのケースをラベル/色マップに含めておらず、内部の生文字列 `"UNKNOWN"` がそのまま UI に表示されていた。「判定失敗」のラベルとグレー配色を追加した
  - D41 と異なり、これは誤情報ではなく表示品質の改善(安全と誤認させる問題ではなかった)

### Fixed
- **出荷 UI (`SecurityDashboard.tsx`) がハードコードされた偽データと未実装の保護機構を表示していた (D41・このセッション最重要)**
  - 「セキュリティ」タブを開くたびに、偽の AI アクセスログ・偽の連絡先インテリジェンス(架空の氏名)・偽のアクションアイテムをハードコードで表示していた。実データ取得元が無いため、偽データではなく空状態を表示するよう変更した(各サブコンポーネントは空配列を正しく処理する)
  - `ai_detect_phishing` がエラーになった場合、無言で「score: 0.15(安全)」という偽の判定にフォールバックしていた。**本物のフィッシングメールを安全と誤信させかねない**重大な欠陥だった。エラー時は専用のエラーメッセージを表示し、スコアバー・偽の安全判定は出さないよう修正
  - 「競合比較カード」で「ローカル AI 推論」(D2: 未実装)・「MLS + PQC 暗号化」(D1: XOR モック)を実装済みの独自機能として表示していた。SECURITY.md(D34)・brand-guidelines.md(D39)・competitive-analysis.md(D40)と同じ欠陥が出荷 UI 自体にもあった。5項目を実装状況どおりに ✓/⚠/✗ に区分し直した
  - **これは文書ではなく実際にユーザーが操作する出荷画面であり、これまでの発見の中で影響が最も直接的だった**

### Fixed
- **`ZeroKnowledgeSearch` 自身の doc コメントも「本番: SQLite FTS5 使用」と誤って主張していた** (D40 の追跡調査)
  - 実際のフィールドはインメモリ `Vec` で、アプリ再起動でインデックスが消える。コメントを実装どおりに訂正した
  - **配線は見送った**: 実際に配線されている `kaname_store::search_messages` は SQLCipher に永続化された LIKE 検索であり、未配線かつ非永続の `ZeroKnowledgeSearch` に置き換えると永続化を失う退行になる

### Fixed
- **`docs/competitive-analysis.md` の「実装した改善」表に、モック/スタブ/未配線の機能が実装済みとして6項目含まれていた** (D40)
  - 件名MLS暗号化(D1)・Dual-LLM型安全(D17)・Firecracker添付分離(D4)・ローカルAI推論(D2)が実装済みと主張していた
  - **新発見**: `kaname-privacy::ZeroKnowledgeSearch` は実装されているが `kaname-ui` から一度も呼ばれておらず、実際の検索(`mail_search`)は平文 LIKE 検索だった。D12/D13/D21 と同じ「実装したが組み付けていない」パターン
  - 該当6項目に実態を注記(⚠️/✅で区別)
- **`launch-keynote-2026.md`/`vision-keynote.md`/`product-film-script.md` に現状確認への導線を追加**
  - これらは Amazon/Apple 流「Working Backwards」を自ら明記した到達目標であり、SECURITY.md/testing-strategy.md/brand-guidelines.md とは性質が異なるため本文は書き換えず、`docs/maturity.md`/`docs/gap-analysis.md` へ導く注記のみ追加した

### Fixed
- **`docs/brand-guidelines.md` の「推奨表現」が未実装機能を主張するマーケティング文言の使用を執筆者に指示していた** (D39・最重要級)
  - 「推奨表現」に `"型システムで保証"`/`"コンパイル時に検証"`(D17: trait 実装0件)と `"RFC 9420 準拠"`(D1: MLS は XOR モック)が含まれていた
  - SECURITY.md(D34)・testing-strategy.md(D36)は「既に書かれた文書が誇張していた」問題だったが、これは**将来書かれるマーケティング文言・UI 文言が誇張することを積極的に推奨する**という、より先行的な害を持っていた
  - 該当2表現を取り消し線付きで「使用禁止」に変更し、D1/D17 解消後にのみ使用可能と明記した

### Fixed
- **`SETUP.md` に D7/D31 と同じ欠陥クラスが3箇所あった** (D38)
  - `git clone` が誤ったリポジトリ(`kaname-app/kaname`)を指していた(D31/D33/D35 と同じ誤り)。`shizukutanaka/kaname` に訂正
  - ディレクトリツリー図が `.github/workflows/` に `ci.yml`/`sbom.yml`/`release.yml` が存在すると記載していたが、実際は空(D7)
  - リリース手順が「`git push origin vX.Y.Z` で CI が自動的にビルド・配布」すると説明していたが、CI 自体が存在しないため配布は起きない
  - いずれも実態(CI 不在、手動配布が必要)に合わせて訂正した。`scripts/release.sh` 自体は実在することを確認済み

### Fixed
- **`docs/performance-history.md` が「実測は v0.2.0 リリース時に追記」と予告したまま、v0.7.1 に至るまで一度も追記されていなかった** (D37)
  - `cargo bench` は D20 により本環境で実行不可、CI ベンチマーク (`.github/workflows/perf.yml`) も D7 により存在しないため、この空白は今後も埋まらない可能性が高いことを明記した
  - v0.1.0/v0.1.4 の歴史的な実測記録は変更していない

### Fixed
- **`docs/testing-strategy.md` がテスト件数・カバレッジ「現状」を実測済みであるかのように主張していた** (D36。SECURITY.md D34 と同種)
  - 「CI 実行マトリクス」節は D7(CI ワークフロー自体が存在しない)を、「カバレッジ目標」表の「現状」列(91%/87%/85%等)は D20(`cargo test`/`npm test` がこの環境で実行不可)を前提にしており、どちらも検証不能な主張だった
  - 文書冒頭に、この環境で未検証であることを明記する訂正を追加した。数値そのものは書き換えていない(このリポジトリの実測値かどうか本セッションでは判定不能なため)

### Fixed
- **末尾のバージョン比較リンクが誤ったリポジトリ (`kaname-app/kaname`) を指していた** (D35。D31/D33 と同じ欠陥クラス)
  - `shizukutanaka/kaname` に訂正した
  - **git tag が一つも作成されていないことを確認した** (`git tag -l` が空)。v0.1.0〜v0.7.1 のどのリリースにもタグが付いておらず、比較リンクはリポジトリを訂正しても404のままになる。タグ作成はリリース権限を持つ人間の判断領域のため本セッションでは行わない

### Fixed
- **`SECURITY.md` が実装されていない保護機構3件を「実装済み」と主張していた** (D34・最重要)
  - 「主要保護メカニズム」節が Dual-LLM 型安全(実際は D17: trait 実装0件)・MLS 暗号化(実際は D1: XOR モック)・Firecracker サンドボックス(実際は D4: no-op)を実装済みと誤って主張していた
  - サポート対象バージョン表も v0.3.x を最新と記載したまま(実際は v0.7.1)だった
  - **セキュリティ方針文書自体が、この製品の README・threat-model・gap-analysis が総力で正そうとしてきた「誇張」を体現していた**。脆弱性報告者が誤った前提で判断しないよう、実態に合わせて訂正した
  - 報告経路・SLA・重大度分類・報奨・監査計画等の運用面は変更していない(人間の意思決定領域)

### Fixed
- **CONTRIBUTING.md の i18n 節が実態と3点ズレていた** (D33)
  - 存在しないディレクトリ (`src/i18n/`。実際は `src/locales/`)、存在しない言語ファイル (`zh-CN.json`/`ko.json`。`Language` 型は宣言しているが JSON 未作成)、存在しない CI 検証 (D7 により CI 自体が無い) を実態に合わせて訂正
  - `git clone` の URL も D31 と同じ誤り (`kaname-app/kaname`) を含んでいたため `shizukutanaka/kaname` に訂正
  - `src/i18n.ts` 冒頭コメントの誤ったファイルパス表記・CI 主張も訂正
  - 実害としてはブラウザ言語が中国語/韓国語のユーザーが日本語へ自動フォールバックするのみで、クラッシュや空表示にはならないことも確認済み

### Added
- **`static-check.sh` に検査8を追加**: `Cargo.toml`/`package.json`/`tauri.conf.json` のバージョン番号が一致していることを検証 (D32)
  - 前PRで v0.6.0 のまま放置されていた3箇所を修正した直後、「次のセッションのために記憶しておくべき」と書いただけで自動化していなかった。これは D25/D26 の教訓 (欠陥クラスは自動化するまで再発防止にならない) をその場で忘れていたことになる
  - 合成的に `package.json` を `0.6.0` に戻して検出されることを確認 (実際に起きたバグをそのまま再現)。復元後に誤検知が無いことも確認済み

### Fixed
- **ビルドマニフェスト3箇所のバージョン番号が v0.6.0 のまま放置されていた**: `Cargo.toml` (workspace、全クレートに波及)、`package.json`、`src-tauri/tauri.conf.json`。v0.7.0/v0.7.1 のリリースカットで README/CHANGELOG/maturity.md は更新したが、実際のビルド成果物に埋め込まれるバージョン番号を更新し忘れていた。すべて `0.7.1` に揃えた

### Changed
- **`docs/threat-model.md` の残存リスク評価3件が D10 (メールパイプライン未配線) 解消前の前提のまま放置されていた** (最重要)
  - **§3.15b (D18, 送信ドメイン認証の独立検証なし)**: 「D10 未配線のため悪用経路は存在しない」から**「D10 解消により現在実際に稼働している」へ格上げ**。`Authentication-Results` ヘッダを暗号検証・authserv-id 検証なしに信頼する設計は、監査時点では理論上の懸念だったが、**接続先 JMAP サーバや経路上の中継を攻撃者が制御・偽装できれば、現在悪用可能**。`docs/gap-analysis.md` D18 も同様に更新
  - **§3.16 (D17, Dual-LLM 型境界)**: 悪用不能な理由を「D10 未配線」から「D2 (LLM 推論がスタブで `llm_bridge` 呼び出しが0件)」に訂正。**LLM 推論を配線する PR は、型境界を同時に塞がない限りその瞬間に悪用可能になる**ことを明記
  - **§3.14 (SVG guard)**: 「添付処理パイプラインに未配線」という記述が誤りだったと判明。`scan_attachments` が実際に `svg_guard::scan_svg` を呼んでおり、D10 解消後は実メール添付に適用されている (安全側の訂正)
  - いずれもコード変更は無く、脅威モデルの記述精度のみを実態に合わせた

## [0.7.1] - 2026-09-14 — CLAUDE.md 不変条件の検証と、自分自身の記録の訂正

v0.7.0 に続き、CLAUDE.md の不変条件 (I5/I6) を初めて検証し、I5 を守る
はずの防衛層が完全に無効だったことを発見・修正した。加えて、v0.7.0
までに書いた D24 の分類を検証し直し、2箇所の誤りを訂正した。
「結論が同じでも理由が間違っていれば次の判断を誤らせる」という
教訓を得たリリース (詳細は docs/socratic-review.md)。

### Fixed
- **README のバッジ・`git clone` 手順が `kaname-app/kaname` (アクセス範囲外のリポジトリ) を指していた** (D31)
  - CI/Security Audit/Platform バッジと `git clone` コマンドの4箇所を実際のリポジトリ `shizukutanaka/kaname` に訂正した
  - `Cargo.toml`/`CLAUDE.md` 等、他13ファイルに残る同種の言及は意図的に変更していない (ブランド名か置き場所かの区別がコードから判断できないため)
- **`examples/README.md` の「JMAP 送受信は未配線」という記述が D10 解消より前の古い記述のまま残っていた**
  - 受信/送信/添付ダウンロード/削除/本人確認/検索/永続化はすべて配線済み。サンプルは「サーバ接続なしで同じ検出器をすぐ試せる」という位置づけに書き直した
- **D24 (a) の分類も一部誤りだった: 「LLM 依存で意図的に未配線」10件のうち8件は LLM 生成ではなく決定論的な防衛策だった** (D30・文書訂正のみ、コード変更なし)
  - D24 (a) は「配線すると偽の AI 出力を表示する」という理由で10件すべてを一括りにしていたが、`audit_ai_output`/`check_action_risk`/`check_memory_trust`/`check_rule_of_two`/`validate_tool_argument`/`record_agent_step`/`reset_trajectory`/`screen_user_input` の8件は `PromptScreener`/`OutputAuditor`/`TieredRisk` 等の決定論的チェッカーを呼ぶだけで、`kaname-ai::llm_bridge` を一切呼んでいない。本当に LLM 生成を要するのは `ai_smart_reply`/`ai_summarize_email` の2件のみ
  - **配線しない判断自体は維持する**: `kaname-ui/src/commands.rs` に実際の LLM 呼び出し経路が一つも無いため、防衛すべき対象が無い現状でこれら8件を UI に繋いでも意味を持たない。LLM 本実装と同時に、その入出力の境界に組み込むのが正しい順序。D24 の分類理由のみを訂正した

### Fixed
- **D24 の分類ミスを発見・修正: `settings_get`/`settings_set` は「内部 API として正当」ではなく、引数を無視するだけの未使用スタブだった** (D29)
  - D24 を書いた時点でこの2コマンドの実装を確認せず「他コマンドから使用される内部 API」と分類していたが、実際は `_account_id`/`_key`/`_value` と使わない引数に `_` を付けたまま `Ok(())`/`Ok(None)` を返すだけで、呼び手は一つも無かった
  - オンボーディング専用の `settings_save_onboarding`/`settings_is_onboarded` は既に `kaname_store::Store::set_setting`/`get_setting` を実際に呼んでいたが、汎用版だけが同じパターンを踏襲せずスタブのまま放置されていた
  - `Store::set_setting`/`get_setting` を呼ぶ実装に置き換えた。呼び出す UI はまだ無いため `static-check.sh` 検査5の WARN は残るが、これは「実装はしたが UI 未着手」という正直な状態であり、隠さず記録する

### Fixed
- **CLAUDE.md I5 (「ログに PII を含めない」) を守るはずの `PrivacyLayer` が完全に無効だった** (D28・最重要)
  - `PrivacyLayer` は `kaname-observability` に実装・テストされていたが、どの tracing subscriber にも登録されておらず、実行時に一度も動いていなかった。`kaname-ui::run()` (`src-tauri/main.rs` から実際に呼ばれるロガー初期化) は `tracing_subscriber::fmt()...init()` だけで `PrivacyLayer` を組み込んでいなかった
  - `tracing_subscriber::registry().with(env_filter).with(fmt::layer()).with(PrivacyLayer).init()` に変更し、実際の subscriber に組み込んだ
  - **さらに `PrivacyLayer` 自身の docstring も実装と食い違っていた**: 「PII 検出時にイベントをドロップする」と書かれていたが、実装は警告ログを追加発行するだけで、PII を含む元のイベントは他の Layer (フォーマッタ) にそのまま伝播し出力されていた。`tracing-subscriber` の `Layer::on_event` には他レイヤーへの伝播を止める権限が無く、真にブロックするには `Filter::event_enabled` ベースの再設計が要る。docstring を実装どおり (検知のみ・非ブロック) に修正した
  - 手動でのワークスペース走査では I5 違反 (ログへの PII 直接埋め込み) はゼロ件を確認済みだが、それはプログラマの注意力のみに依存する脆い保証であり、設計されていた多重防衛層が無効だったのは重大な見落としだった
  - `cargo check` は D20 により実行できず、この修正が型検査を通ることは未検証。`Filter` ベースへの再設計 (実際にブロックできるようにする) も未着手 (残作業として記録)

### Added
- **`static-check.sh` に検査6を追加**: CLAUDE.md 不変条件 I6 (「`unwrap()` は本番コードに使用禁止」) を検証 (D27)
  - `#[deny(clippy::unwrap_used)]` で強制する設計だが、`clippy` は D20 (組織のエグレスポリシー) により一度も実行されておらず、I6 が守られているか未検証だった
  - ワークスペース全体を手動走査した結果、**本番コードでの `.unwrap()` 使用は 0 件**であることを確認 (`#[cfg(test)] mod` / 個々の `#[test]` 関数は正しく除外)。コード変更は無く、検証結果のみ
  - 再発防止として検査として自動化。合成的に本番コードへ `.unwrap()` を注入して検出されること、行番号が正しく報告されること、テストコード内では誤検知しないことを確認済み (docs/gap-analysis.md D27)

## [0.7.0] - 2026-09-14 — 「到達可能 UI から呼ばれないコマンド」を仕分けし、検証ツール自体の欠陥を2件直したリリース

v0.6.0 の「到達可能な UI がすべて実装を呼ぶ」を土台に、その**逆方向**
(実装済みなのに UI から届かないコマンド、D24) を仕分けて 5 件中 5 件を
解消し、さらに検証ツール自身に眠っていたバグを 2 件 (D25・D26) 見つけて
直したリリース。

### このリリースで学んだこと (docs/socratic-review.md に詳細)
- 「配線した」と言えるのは、その先が実装であることまで確認したときだけ
  である (D24)。ただし配線しないことが正しい場合もある — LLM がスタブの
  現状で AI 系コマンドを配線すれば偽の出力を表示することになる
- 静的検証ツール自体にも、検証対象のコードと同じ水準の注意が要る。
  一度作った検査は「一般化」した瞬間に別の欠陥を持ちうる。合成的に
  既知のバグを再現し、検出→復元を確認する手順を経て初めて信用できる
  (D25・D26 とも、最初に書いた検査の実装は検出したかったバグを
  素通りさせていた)

### Fixed
- **D25 と同じ欠陥クラスのフロントエンド版が見つかった** (D26)
  - `app.test.ts` の `makeEmail()` ヘルパーが、`KanameApp.tsx` 削除 (PR #82) で消えた `Email` 型を import せずに参照していた。どこからも呼ばれていない未使用コードでもあった。`tsc`/`vitest` が動く環境であれば型エラーで即発覚するはずが、D20 により実行できず3セッション気付かれなかった
  - `makeEmail()` を削除

### Added
- **`static-check.sh` に検査6を追加**: TypeScript の「未 import・未定義の型参照」を検出 (D26 の再発防止)
  - 大文字始まりの識別子が、import 文にも同一ファイル内の型/値定義にも無いまま型位置 (`: Type` / `Generic<Type>`) で使われているケースを機械的に検出する
  - 最初の実装は `Partial<Email>` のようなジェネリクス**使用**側まで「ローカルなジェネリクス宣言」として誤って許可しており、検出したかったバグそのものを素通りさせていた。合成的な回帰テスト (壊れたコードを一時的に再現し、検出→復元を確認する) で発覚し、`function f<T>`/`class C<T>` の宣言側にのみ限定して修正した
  - ワークスペース全体で誤検知ゼロを確認

### Added
- **`analyze_raw_email` (mail_import_eml/mail_open 共通の解析経路) に初のユニットテストを追加**
  - これまで一度もテストされていなかった。D25 の static-check 強化の過程で発覚
  - 安全なメール (BEC/OOBV/Deepfake すべて無反応)、送金 BEC メール (OOBV 強い推奨)、金融文脈を伴う音声添付 (Deepfake High 警戒)、二重拡張子の危険添付、の4ケースを実データ (RFC 5322 バイト列) で検証

### Fixed
- **`mail_list` 削除 (PR #86) の巻き添えで放置されていたコンパイルエラー** (D25)
  - `crates/kaname-ui/src/commands.rs` のテストモジュールに `mail_list("inbox".into(), ...)` を呼ぶテストが2件残っており、`mail_list` 自体は既に削除済みだった。`cargo check` を実行できない環境 (D20) でこの種のリグレッションを防ぐために作った `static-check.sh` 自身が、これを見逃していた
  - 原因: 検査2がハードコードされたシンボル一覧しか見ておらず、一覧に無い関数の削除は検出できなかった。一覧を都度更新する運用は同じ穴を繰り返す設計だったため、リポジトリ全体を走査する一般的な方式に置き換えた
  - 壊れていた2テスト (`mail_list_respects_limit`/`bec_dangerous_in_mock`) はモック実装を前提にしていたため削除

### Added
- **`static-check.sh` 検査2を一般化** (D25 の根本対応)
  - ハードコードされたシンボル一覧を廃止し、リポジトリ全体から「裸で呼ばれているが定義も import も見つからないシンボル」を機械的に検出する方式に変更
  - 一般化の過程で見つけた誤検知の原因をすべて修正: 属性 (`#[cfg(...)]`)・raw文字列の閉じハッシュ数不一致・char リテラル (`'"'`) と文字列リテラルの処理順序・文字列内のバックスラッシュ行継続 (DOTALL 不足)・複数行 `use` インポート・行末コメント (従来は行頭コメント専用行しか除去していなかった)・Rust 予約語 (`if(`/`let(`/`pub(crate)` 等)・クロージャ束縛 (`let f = |...|`)
  - 修正後、ワークスペース全体で誤検知ゼロを確認。合成的に削除済み関数への参照を注入したテストで正しく検出できることも確認済み

### Added
- **Deepfake (音声/動画添付) の警告をメール詳細に配線** (D24 (b) を完全解消)
  - `analyze_raw_email` が添付検査 (`scan_attachments`) の結果を使い回し、`DeepfakeAdvisory::evaluate()` を直接呼ぶ。`ImportedEmail.deepfake_advisory` として埋め込み、独立コマンド `deepfake_evaluate` への往復は発生させない
  - 受信トレイの詳細パネルと「ファイル解析」タブの両方に表示: 高警戒 (金融文脈あり) は目立つ警告として、それ以外の音声/動画添付は控えめな注記として表示。推奨アクション (`OobvBeforePlay`/`PlayInSandbox`) に応じて文言を出し分ける
  - これで D24 (b)「配線すべき」5 件 (`mail_download_attachment`/`mail_trash`/`history_mark_verified`/`oobv_recommend`/`deepfake_evaluate`) が**全件解消**。独立コマンドとしての `oobv_recommend`/`deepfake_evaluate` は UI から未到達のままだが、判定ロジックは配線済みで、静的検査の WARN は意図した状態として D24 に記録済み
- **帯域外検証 (OOBV) の推奨をメール詳細に配線** (D24 (b) をさらに一部解消)
  - `analyze_raw_email` (`mail_open`/`mail_import_eml` 共通の解析経路) が本文を解析する時点で `OobvRecommender::recommend()` を直接呼び、判定結果を `ImportedEmail.oobv_level`/`oobv_message` として埋め込んだ。独立コマンド `oobv_recommend` を素の本文を渡して呼ぶより、往復も本文の露出も増えない
  - `oobv_recommend` の `message_i18n_key` は i18n カタログに対応するキーが存在しない (`kaname-i18n` は出荷バイナリから到達不能、D19) ため、カタログが繋がるまでは完成した日本語メッセージを直接組み立てて返す
  - 受信トレイの詳細パネルと「ファイル解析」タブの両方に表示: 強い推奨 (送金・認証情報など) は目立つ警告として、任意の推奨は控えめな注記として表示
  - 独立コマンド `oobv_recommend` 自体は今も UI から未到達 (判定ロジックは配線したが、コマンドという経路は使っていない)。将来の直接呼び出しに備えたテスト済み内部 API として残す
- **BEC 警告バナーに送信者の本人確認を配線** (D24 (b) をさらに一部解消)
  - `history_mark_verified` は登録済みだが呼び手がゼロだった。フロントエンドは `account_id` を持っていなかったため、他コマンド (`mail_open`/`mail_fetch`) と同様に `current_account_id()` で内部解決するようシグネチャを `(account_id, email)` → `(email)` に簡素化
  - BEC 警告バナー (ADVISORY 以上) に「本人確認済みにする」ボタンを追加。電話などの帯域外手段で確認が取れた送信者をマークでき、以降の BEC 判定で信頼シグナルとして働く (`kaname-bec` の `user_verified`)
  - 対象の contacts 行は `mail_fetch` の `record_received` が受信のたびに作成するため、メール一覧に出ている送信者であれば必ず存在する
- **受信トレイに削除・添付ダウンロードを配線** (D24 (b) を一部解消)
  - 詳細パネルにツールバーを追加: 「🗑 ゴミ箱へ」(`mail_trash`。確認ダイアログ経由)・「✕ 閉じる」。以前は `onClose` が props として存在するのに呼び出し元の UI 要素が無かった
  - 添付を**全件**表示し (従来は危険なものだけ)、各添付に「ダウンロード」ボタンを追加。新規 `mail_list_attachment_blobs` でファイル名→blobId を解決してから `mail_download_attachment` を呼ぶ (`mail_open` の添付検査結果はバイト列由来で blobId を持たないため)
  - 危険と判定された添付は既存仕様どおりディスクに書かれず、理由が表示される

### Added
- **発見した欠陥クラスを `scripts/static-check.sh` に自動化** (マスク式の第5段階「自動化」)
  - 検査3: `src/main.tsx` からの import 到達可能性 (死蔵モジュールの検出)
  - 検査4: `invoke("name", {args})` と Tauri コマンド定義の**名前・引数の整合** (camelCase → snake_case 変換、shorthand プロパティ対応)
  - 検査5: 登録済みだが UI から呼ばれないコマンドの列挙 (WARN)
  - v0.6.0 までに人手で 4 回発見した欠陥は、どれも機械的に検出できたクラスだった。測定を毎回捨てていたことが再発の原因

### Fixed
- **`AdminDashboard` が死蔵し、存在しない 3 コマンドを呼んでいた**: どこからも描画されないまま `admin_get_dashboard` / `admin_get_audit_log` / `admin_list_incidents` を invoke していた。削除し、`ComposeAdmin.tsx` を実態に合わせ `Compose.tsx` に改名。**ファイルは到達可能だがコンポーネントは死んでいる**という、検査3では見つからない欠陥だった
- **`mail_list` が空配列を返す偽実装だった**: エラーではなく `Ok(Vec::new())` を返すため「メールなし」と表示される。呼び手はゼロで `mail_fetch` に置き換え済みのため削除

### Changed
- **オフライン時は保存済みメールを表示**: `mail_fetch` が失敗したら `mail_list_stored` にフォールバックし、「サーバに接続できないため保存済みのメールを表示しています」と明示する。取得できないことは読めないことを意味しない

## [0.6.0] - 2026-09-02 — 「到達可能な UI がすべて実装を呼ぶ」完成リリース

v0.5.0 が「検出器を組み付けた」リリースなら、v0.6.0 は**出荷 UI が実際に
その検出器と永続化に届く**ことを実測で確認したリリース。

### 完成の定義 (docs/socratic-review.md)
エントリポイントから到達可能な UI (**9/9**) が呼ぶコマンドがすべて実装
(`not_wired` **0 件**) で、その実装が外部キーやセッション等の前提条件を
自分で満たすこと。この状態に到達した。

### 本リリースで見つかり、直した「動いていなかったもの」
| 記録上の状態 | 実態 | 修正 |
|---|---|---|
| 受信トレイを配線した | モック専用画面が描画され、実配線版は未 import | 入れ替え (D21) |
| 送信時に DLP がブロック | 送信画面に到達不能、引数不一致で必ず失敗 | 配線 + 修正 |
| 永続化・検索を実装 | Store が開かれず、開いても FK 違反 | 自動オープン + ensure (D23) |
| BEC 詳細を表示 | 3 コマンドがスタブ | `mail_open` で .eml と同一経路 |

### 依然として真でないもの (隠さない)
MLS (XOR モック)・ローカル LLM (固定応答)・サンドボックス (no-op) は設計のみ。
`cargo check` / `vitest` は組織のエグレスポリシーにより未実施 (D20)。
SQLCipher 鍵は OS キーチェーン未統合。


### Fixed
- **永続化は一度も成功し得ない状態だった (最重要)**
  - `history_open` はコマンドとして存在したが**どの UI からも呼ばれておらず**、Store は出荷製品で一度も開かれていなかった。「Store 未接続なら何もしない」設計のため、永続化・検索・送信者履歴が**無言で無効**だった。起動時に `history_open_default` で `<data_dir>/kaname/history.db` を開く
  - さらに `PRAGMA foreign_keys = ON` なのに `accounts`/`mailboxes` への本番 INSERT が存在せず (テストの `seed_account` のみ)、Store を開いても `save_message`/`record_received`/`set_setting` は **FK 違反で必ず失敗**していた。書き込み前に `ensure_account`/`ensure_mailbox` を通す
  - SQLCipher 鍵は `history.key` (0600) に保存。**OS キーチェーン未統合のため同一ユーザー権限のプロセスからは読める**ことを明記 (他ユーザー・持ち出しへの保護であり、同一アカウント上のマルウェアへの保護ではない)
- **オンボーディングを配線 (D22 解消)**: `settings_save_onboarding` を `settings` テーブルへ実装し、初回起動時に表示。到達可能フロントエンドモジュール **8/9 → 9/9**、`not_wired` スタブ **0 件**
- **出荷 Inbox が呼ぶスタブ 3 件を実装** (`mail_open` / `mail_get_mailboxes`)
  - PR #82 で到達可能にした `Inbox` は `mail_get_body` / `bec_get_score` / `mail_get_mailboxes` を呼んでいたが、**3 つともスタブ**でメールを開くたびに必ず失敗していた。到達可能にした画面がスタブを呼ぶなら到達させた意味がない
  - `mail_open(email_id)`: JMAP の `blobId` (生 RFC 5322 全体) を `download_blob` で取得し、ローカル `.eml` と**同じ** `analyze_raw_email` に通す。本文・BEC スコア・シグナル・添付検査・DLP・リンク評価が一度に得られ、**新しい解析コードは 0 行**。`bec_get_score` という別コマンドは不要になり削除
  - `mail_get_mailboxes`: `JmapClient::get_mailboxes` を配線
  - 受信トレイの詳細ビューで危険な添付と機微情報 (DLP) も表示
  - **作成画面の「✨ AI 草案」を削除**: 定型文を「AI 草案」と表示して挿入しており、LLM がスタブ (D2) である以上 AI 出力を偽っていた
  - 呼び手ゼロのスタブ `mail_query_emails` / `bec_get_score` を削除。残る `not_wired` は `settings_save_onboarding` のみ (D22)
- **出荷 UI がモック専用コンポーネントを描画していた (最重要)**
  - 受信トレイは `KanameDesign` を描画していたが、同コンポーネントは自身のコメントが認めるとおり **invoke を一切呼ばないモックデータ専用**だった。一方 `mail_fetch` / `mail_search` / `bec_get_score` を実際に呼ぶ `Inbox` は**どこからも import されておらず死蔵**していた。両者を入れ替え、受信トレイが実データを表示するようにした
  - **メール送信に UI から到達できなかった**: `mail_send` を呼ぶのは未到達の `ComposeAdmin` のみ。「作成」ビューとして配線した
  - **送信は配線しても実行時に必ず失敗する状態だった**: フロントは `{ req: { to, subject, body, draft_id } }` を送っていたが Tauri コマンドは `(from, to, subject, body)` を取る。引数形を合わせ、差出人入力欄を追加 (JMAP セッションはアカウントのメールアドレスを公開しないため)
  - **UI が実装されていない暗号化を「対応済み」と表示していた**: 作成画面の MLS インジケータは宛先ドメインの接尾辞だけを見て判定していたが、`kaname-mls` は XOR モック (D1) で実際には暗号化されない。常に非対応を返すよう修正
  - `EmailRow.triage` が `"important"` 固定だった。実装済みの `kaname_core::ux_features::TriageEngine` を配線 (フロントエンドの TypeScript 重複実装は削除し、判定元を一つにした)

### Removed
- **死蔵していたモック専用フロントエンド 2,284 行を削除**: `KanameApp.tsx` (1,134 行・ハードコードされたデモメールと `triageEmail` の重複実装)、`KanameDesign.tsx` (1,150 行・モック専用の受信トレイ)。到達可能なフロントエンドモジュールは **7/11 → 8/9**

### Added
- **添付ファイルのダウンロード** (D10 の最後の項目を解消 — **D10 完全解消**)
  - `kaname-jmap` に `download_blob` を追加 (`download_url` テンプレート置換 + Bearer 認証、25 MB 上限を Content-Length と実読み取りの二重で確認)
  - `kaname-render` の添付検査を `scan_attachment_bytes(filename, mime, bytes)` として公開関数に抽出し、フォルダ一括スキャンと単一 blob の両方で同一の検査を適用
  - `mail_download_attachment` コマンド: **ディスクに書く前に必ず検査**し、`is_dangerous` なら**保存せず**リスク一覧のみ返す (kaname-sandbox が no-op の現状、実行は許さず「検査して警告」に徹する)
  - `sanitize_filename` で添付名のパストラバーサル・制御文字を無害化 (添付名は攻撃者制御の入力)
- **ソクラテス問答による製品総括** `docs/socratic-review.md` — 「これはメールクライアントか」「セキュリティは本物か」「最大の弱点は何か」「完成とは何か」の自問と、長所・短所・改善点の一覧

- **メール本体の永続化と検索** (D10 の残りを解消)
  - `messages` テーブルはスキーマもインデックスも完備していたが、**INSERT/SELECT がワークスペース全体でゼロ件**だった。`save_message` / `list_messages` / `search_messages` を実装
  - **冪等性**: `id` を `sha256(account_id + jmap_id)` で決定論的に採番し `ON CONFLICT DO UPDATE`。再取得しても行が重複しない
  - **`body_encrypted` には書かない** — MLS がモック段階 (D1) の現状で暗号化列に平文を入れると「暗号化済み」と偽ることになる。一覧表示に必要な `body_preview` のみ保存
  - **検索は LIKE ベース** — FTS5 は SQLCipher ビルドで有効とは限らず、有効性を確認できない環境で依存するのは危険。利用者の検索語の `%` `_` はエスケープする
  - 受信箱の検索欄は**ハンドラ未バインドの「飾り」だった**ため `mail_search` に接続
  - 一覧読み込みを未配線の `mail_query_emails` から実装済みの `mail_fetch` に切り替え

## [0.5.0] - 2026-07-18 — 全検出器を製品に組み付けた「組み立て完了」リリース

v0.4.0 で確立した解析パイプラインに、**実装済みだが眠っていた部品を
すべて接続**したリリース。到達可能クレートは **10 → 18 / 27**。

### 一貫して見つかった構造
「実装は揃っているのに、渡す経路が1つ無いだけで部品群が眠る」パターンが
繰り返し見つかった。今回接続したものはすべてこれに該当する:

| 眠っていたもの | 欠けていた1経路 |
|---|---|
| BEC の URL シグナル / quishing の URL 評価 | 本文から URL を抽出する関数 |
| 添付検出器5種 (MIME偽装/polyglot/危険拡張子/SVG/メタデータ) | `parse()` が添付バイトを捨てていた |
| カレンダー招待検査 (CalPhishing) | 添付経路への接続 |
| JMAP 送受信 | `kaname-ui` が `kaname-jmap` に依存していない |
| BEC の履歴シグナル | Store の `SenderProfile` を BEC に渡す変換 |
| SaaS リンク安全性 (D13) | 抽出済み URL への適用 |
| 送信者文体認証 (D12) | プロファイル蓄積の器 |
| トラッキングピクセル検出 | `analyze_body_risks` への追加 |

### Added
- **JMAP サーバとの送受信** — 受信メールがファイル解析と同じ検出器を通る。送信前に DLP (`Outbound`) でブロック
- **送信者履歴の永続化** (SQLCipher) — BEC の履歴シグナルが初めて発火
- **添付ファイル検査** — MIME偽装 / polyglot / 危険拡張子 / SVGスクリプト / メタデータ / カレンダー招待
- **本文リンク評価** — 短縮URL・タイポスクワット・自由TLD・SaaS リンク安全性
- **送信者文体認証 (SSA)** — アカウント乗っ取り検出
- **トラッキングピクセル検出**
- `scripts/static-check.sh` — `cargo check` が使えない環境での構文・未定義関数検証

### Fixed
- **回帰修正**: PR #64 の編集で `analyze_body_risks` が定義ごと誤削除され、コンパイルエラーの状態が 5 PR 検出されなかった問題 (D20 の実害)

### 意図的に含めないもの
`kaname-mls` (モック暗号) と `kaname-sandbox` (no-op) は、**組み込むと
「暗号化/隔離されている」と偽ることになる**ため実装が入るまで含めない。
`mockserver`/`tests` は開発用、`billing` はスコープ外、
`core`/`continuity`/`i18n`/`tray` は本体機能が固まってから。

### 既知の制約
- **型検査 (`cargo check`) は未実施**。組織のエグレスポリシーにより
  `static.crates.io` が遮断されている (D20)。`scripts/static-check.sh` で
  構文検証のみ実施
- メール本体の永続化・検索・添付ダウンロード・MLS 暗号化・
  ローカル LLM 推論は未実装

### Added
- **トラッキングピクセル検出を接続** — README が「デフォルトでブロック」と謳う機能の実体 `kaname-privacy` は実装済みだが未接続だった。検出件数とドメインを本文リスクに報告する
- **残るクレートの仕分けを文書化** — 到達可能 18/27。残る 9 個は**意図的に含めない**理由を `docs/maturity.md` に明記。特に `kaname-mls` (モック暗号) と `kaname-sandbox` (no-op) は、**組み込むと「暗号化/隔離されている」と偽ることになる**ため実装が入るまで含めない
- **送信者文体認証 (SSA) を接続しアカウント乗っ取り検出を有効化** — `kaname-ssa` (1209行) は文体プロファイルによる乗っ取り検出と `EmailStyleFeatures::extract()` を実装済みだが**孤島クレート**だった (D12)。送信者ごとに文体プロファイルを蓄積し、逸脱を警告する。**判定してから取り込む**順序にした (取り込んでから判定すると、なりすましメール自身がプロファイルを引き寄せて検出が鈍る)。`Date` ヘッダが無い場合は評価しない (`send_hour` を 0 で代用すると「深夜送信」という誤シグナルを生むため)
- **SaaS リンク安全性判定を本文リンクに接続** — `kaname-saas-guard` (1556行、偽 SaaS ドメイン検出・SaaS リンク経由のプロンプト注入・OAuth state 検証) は**どこからも依存されない孤島クレート**だった (D13)。本文リンクは既に抽出済みだったため、そこへ載せて到達可能にした。`Warn` 以上のみ報告し `Safe`/`Caution` は出さない (通常の SaaS 通知でも出るため、警告疲れを避ける)
- **送信者履歴を永続化し BEC の履歴シグナルを有効化**
  - `kaname-bec` は履歴シグナル (初回連絡 / 久しぶりの連絡 / 普段と違うトピック / 検証済み) を実装済みだが、`sender_history` に常に `None` を渡していたため**一度も発火していなかった**
  - `kaname-store` には `SenderProfile` の CRUD が実装済みで BEC の `SenderHistory` と対応する形だった。**両者を繋ぐコードが無いだけ**だったため配線
  - `history_open` / `history_close` / `history_mark_verified` を追加。受信時に `record_received` で履歴を蓄積
  - **履歴が無い場合は `None` のまま**にし、BEC に履歴シグナルを評価させない (履歴の不在を「初回連絡」と断定しないため)
  - `user_reported_malicious` は Store 側に列が無いため **`false` 固定** — `true` と偽ると危険側の判定が不当に強まるため、列が追加されるまで保守的に扱う
  - 日付計算は `chrono` を使わず自前実装 (履歴シグナルは日単位の粗い粒度で足りるため、新規依存を増やさない)
- **JMAP サーバとの送受信を配線 (D10 の中核を解消)**
  - `kaname-ui` が `kaname-jmap` に依存していなかったため、出荷バイナリからサーバへ到達する経路が**コンパイル時点で存在しなかった**。`kaname-jmap` 自体は RFC 8621 準拠の実装が揃っており、**配線するコードを書くだけ**で動く状態だった
  - `mail_connect` / `mail_disconnect` / `mail_fetch` / `mail_send` を実装・登録
  - **受信した実データが、ファイル解析と同じ BEC 検出器を通る** (一覧の各通に判定を付与)
  - **送信前に DLP (`Direction::Outbound`) を実行し、`Block` 判定なら送信しない** — これが DLP 本来の用途であり、受信側検査と対になる
  - **認証情報は永続化しない**: Bearer トークンはメモリ内にのみ保持。`kaname-store` の鍵管理が keyfile フォールバックを含む現状では平文同然で置くことになるため、安全に保管できるまで保管しない方針
  - UI に「サーバ接続」タブを追加 (`src/ui/MailConnect.tsx`)

### Fixed
- **回帰修正: 誤って削除された `analyze_body_risks` を復元** — PR #64 の編集で定義ごと巻き込まれ、呼び出しだけが残ってコンパイルエラーの状態が **5 PR にわたり検出されなかった**。`cargo check` が使えない環境 (D20) の実害
### Added
- **`scripts/static-check.sh`** — `cargo check` の代替となる静的検証。全 Rust ファイルの構文チェックと「定義が消えた関数の呼び出し」検出を自動化。上記回帰を受けて追加 (型検査の代替にはならないことも明記)
- **添付ファイル検査を解析パイプラインに接続**
  - `kaname-render` には添付検査 (MIME 偽装 / polyglot / 危険拡張子 / SVG スクリプト / メタデータ) が揃っていたが、**`parse()` が `AttachmentHeader` にバイト列を保持せず捨てていた**ため、検出器に渡す経路が無く一つも動いていなかった
  - `kaname_render::scan_attachments()` を新設。バイト列はクレート内で完結させ (`AttachmentHeader` は変更しない)、検査結果のみ返す。1 添付あたり先頭 10 MB まで検査
  - 単体解析: 添付を危険度付きで表示 (危険/問題なし バッジ + リスク文言)
  - フォルダ一括解析: 危険な添付の件数を一覧に表示 (`attachment_risk_count`)
  - **メタデータのみの検出は `is_dangerous = false`** — 作成者情報や GPS はプライバシー通知であって実行リスクではないため
  - サンプル `06-dangerous-attachment.eml` を追加 (二重拡張子 `.pdf.lnk` + `image/png` を装った PE 実行ファイル)
  - **カレンダー招待 (.ics) の検査も接続** — `calendar_guard` は実装済みだが未接続だった。招待は「添付」として届くため `scan_attachments` に載せた。`Danger` のみ実行リスク扱いとし `Caution` は注意喚起に留める。サンプル `07-malicious-calendar.eml` を追加 (CalPhishing 自動登録永続化 + DESCRIPTION へのプロンプト注入)
- **本文リンクの評価を解析パイプラインに接続**
  - `kaname-bec` の URL 評価シグナルと `quishing::evaluate_url` (悪性ドメイン/短縮URL/タイポスクワット/自由TLD) は実装済みだったが、**本文から URL を取り出す関数が無いだけで一度も実データで発火していなかった**。`extract_urls_from_text` を新設して接続
  - 単体解析: 抽出 URL を BEC へ供給し、リンクの評判判定結果を本文リスクに併記
  - フォルダ一括解析: リンクドメインを `kaname-radar` のキャンペーン相関に供給。各メールの DLP 件数も一覧に表示 (`dlp_count`)
  - サンプル `05-malicious-link.eml` を追加 (短縮URL + 数字置換タイポスクワット + 自由TLD)

## [0.4.0] - 2026-07-18 — ローカル・メールセキュリティ解析ツールとして完結

イーロン・マスクのアルゴリズム (要件を疑う → 削除する → 簡素化する → 組み立てる)
を適用し、**「部品は揃っているが製品として動かない」状態を解消**したリリース。

### 疑って突破した3つの要件

| 疑った前提 | 結果 |
|---|---|
| 「BEC 検出には LLM が必要」 | **要件を削除**。10シグナル中9つはモデル不要のため `BecDetector::deterministic_only()` を追加し出荷可能にした |
| 「メールはサーバから取得しなければならない」 | **ローカル `.eml` で突破**。サーバも認証情報も不要で実メールがパイプラインを流れるようになった |
| 「検証にはネットワークが必要」 | **rustc 1.94.1 が直接使えた**。変更ファイル全ての構文チェックを実施 |

### 発見した根本問題
依存グラフの実測により、**出荷バイナリに到達可能なのは 27 クレート中 10 個のみ**で、
看板機能の `kaname-bec` (110+ テスト) すら製品に含まれていないことが判明した (D19)。
「部品を作る」のをやめ「組み立てる」方針に転換した。

### Added
- **実メール解析** (`mail_import_eml` + 「ファイル解析」タブ) — MIME 解析 → 送信ドメイン認証の評価 → BEC 判定 → サニタイズ → 本文リスク検出を実データで実行
- **フォルダ一括解析** (`mail_scan_folder`) — 危険度順トリアージ + **複数メール横断のキャンペーン検出** (`kaname-radar` を初めて動作させる唯一の入口)
- **DLP による機微情報検出** (`Direction::Inbound`) — 受信メールに機微情報が含まれる事実を転送・返信前に警告
- **動作確認用サンプル** (`examples/emails/` 4通 + 手順書) — キャンペーン検出も試せる構成

### Changed
- 固定値を返していた6コマンドをすべて**実際の検出結果**に接続 (`ai_detect_phishing` / `mail_list` の `bec_verdict` / `mail_get_summary` / `mail_get_body` ほか)
- **未使用だった9つのレンダリング系検出器**を本文表示時に実行するよう接続
- 到達可能クレート **10 → 13** (`kaname-bec` / `kaname-radar` / `kaname-dlp`)

### Removed
- **偽の AI 出力を削除** — 要約・スマートリプライは固定文字列を返しつつ `local_inference: true` と成立していない保証を主張していた。未実装であることを正直に返すよう変更

### Fixed
- `mail_get_body` のフロント/バックエンド型契約不一致 (`String` vs `BodyDto`)
- `magic_bytes` の SVG 検出が先頭256バイトのみで偽装を見逃していた問題

### 既知の制約
サーバとのメール送受信 (JMAP)、永続化、アカウント設定 UI、検索、添付ダウンロード、
MLS 暗号化、ローカル LLM 推論は**未実装** (いずれもネットワークが前提)。
また crates.io にアクセスできない環境のため **`cargo check` による型検査は未実施**。
詳細は `docs/maturity.md` / `docs/gap-analysis.md` を参照。

### Changed
- **「組み立て」フェーズ — 部品を製品に組み付ける (イーロン・マスクのアルゴリズム適用)**
  - **依存グラフの実測**により、出荷バイナリに到達可能なのは **27クレート中10個のみ**で、`kaname-bec` (看板機能・110+テスト) すら製品に含まれていないことが判明 (gap-analysis **D19**)
  - **LLM という要件自体を削除**: `BecDetector` は `Box<dyn LocalLlm>` を必須としたが実装はテスト内のみで、これが BEC 出荷を阻んでいた。10シグナルファミリーのうち9つはモデル不要の決定論的ロジックであるため、`NullLlm` と `BecDetector::deterministic_only()` を追加して LLM なしで動作可能にした
  - **BEC 検出を実際に実行**: `ai_detect_phishing` (固定値 `score: 0.12`)、`mail_list` の `bec_verdict` (モックに手書き)、`mail_get_summary` (固定値) をすべて実際の判定結果に接続
  - **HTML サニタイズ経路を実際に実行**: `mail_get_body` は固定文字列を返しており `kaname-render` のサニタイズが一度も走っていなかった。`sanitize_html` → `to_srcdoc` の実経路に接続し、フロントとの型契約不一致 (`String` vs `BodyDto`) も解消
  - **偽の AI 出力を削除**: `ai_summarize_email` は固定要約を返しつつ `local_inference: true` と成立していない保証を主張していたため、risk のみ本物にし要約は未実装と明示 (`local_inference: false`)。`ai_smart_reply` の固定3文は削除し未実装エラーに変更
  - 到達可能クレート **10 → 11**。新規外部依存はゼロ
  - **依然としてメールの取得元は `mock_emails()`** (D10)。実メールが流れれば同じ経路がそのまま処理する

### Added
- **docs/research-2026-07-part2.md**: セッション横断の研究反映マップと構造的発見の統合
  - 2026年研究動向 (CaMeL/FIDES のアーキテクチャ保証収束、LLMail-Inject/ARGUS、画像ベース注入、DKIMリプレイ、動的QR、deepfake増強BEC 40%) の総括
  - 研究 → 実装 (PR #25〜#33) の対応表
  - 構造的発見 (D10 配線欠如 / D16 添付AI経路未配線 / D17 型境界の宣言と実装の分離) の統合
  - **ネットワーク解放を前提とした優先ロードマップ** (P0 検証 → P1 型実効化 → P2 配線)

### Changed
- **Dual-LLM 型不変条件の実効性監査と正直化 (最重要)**
  - 2026年の out-of-band 防御研究 (CaMeL/FIDES/Progent、arxiv 2606.26479) が「振る舞いではなくアーキテクチャによる保証」へ収束したのを受け、Kaname が公言する**より強い「コンパイル時の型強制」が実際に成立しているか**を実コードで検証した
  - **結果: 型境界の「定義」は堅牢だが「実装」がそれを通っていない**。ワークスペース全体で `impl QuarantinedLlm for`/`impl PrivilegedLlm for` が **0 件**で、実推論経路 `llm_bridge` は生 `&str` API。`as_text()` は `pub` で I1 は規約。`Content<L>` の `Deserialize` derive により `Content<Trusted>` を JSON 偽造可能。`subprocess.rs` は P-LLM に `(allow network-outbound)` を与えており CLAUDE.md I4 と矛盾 (参照先 `resources/seccomp/` も不在)
  - **良いニュース**: I3 の中核 (フィールド private / 公開コンストラクタ2つのみ / `from_validated` が `pub(crate)` / `unsafe` ゼロ / `compile_fail` テスト有り) は本物
  - **悪用可能な経路は現時点で存在しない** (D10 でパイプライン未配線・推論もスタブ)。問題は「配線時に確実に穴になる構造」で、特に**型安全な trait を誰も実装していないため配線時の最短経路が型を迂回する側にある**
  - README の「コンパイル時型安全」節・`docs/maturity.md`・`docs/threat-model.md` §3.16 を実態に合わせて修正。誤導していた doc コメント (`as_text` の「Q-LLM 内部のみ」、`Content` の「型変換は禁止される」) も是正
  - 修正手順を `docs/gap-analysis.md` **D17** に file:line 付きで記録。**中核型の derive 変更はワークスペース全体の再コンパイルを要するため、`cargo check` が実行できない現状では意図的に実施していない**

### Added
- **kaname-render SVG のマルチモーダル・プロンプト注入検出** (`svg_guard`)
  - 攻撃 (Polyglot SVG Attack): SVG は「画像」でありながら XML のため、`<desc>`・**XML コメント (描画されない)**・**CDATA セクション**に命令を潜ませられる。人間の目には正規の画像でも、それを処理する AI は指示として読んでしまう
  - 従来の `svg_guard` は `<script>`・イベントハンドラ等の**ブラウザでのスクリプト実行**のみを見ており、この経路は未検出だった
  - `SvgRisk::PromptInjectionAttempt` を追加。**同一クレートの `calendar_guard` の先例をそのまま踏襲**し `kaname_screen::PromptScreener` に委譲 (原文のまま渡す / `Blocked` のみ採用 / `HighEntropy` は除外して誤検出防止)
  - `SvgRisk::XmlExternalEntity` を追加 — `<!DOCTYPE`/`<!ENTITY` による XXE 形式ペイロード・billion laughs 型 DoS の入口を検出
  - 出典: [arxiv 2603.03637](https://arxiv.org/abs/2603.03637) / CSA research note (2026-03)「Image-based Prompt Injection」— 画像埋め込み命令が**テキスト層のサニタイズを迂回**し、ステルス条件下で最大 **64% の攻撃成功率**。XML/SVG では CDATA 悪用と XXE 形式ペイロードが名指しされている
  - テスト6件追加 (desc/XMLコメント/CDATA の注入検出、XXE 検出、**通常の日本語 SVG の非誤検出**、抽出器の網羅性)
- **kaname-render 動的QR・テキストQR亜種の検出強化** (`quishing`)
  - **動的 QR**: 短縮 URL / QR リダイレクトサービス (bit.ly, tinyurl, qrco.de, flowcode.com 等) を `Suspicious` 判定。配信時は無害なページを指しておき、検査通過後にフィッシング先へ差し替える手法のため、スキャン時点の宛先検証では防げない — 検証不能な参照そのものを疑う設計。サブドメイン形式 (`go.bit.ly`) も対象
  - **テキスト QR の文字集合拡張**: 罫線ブロック8種のみ → 幾何学記号 (■□●○等)・絵文字ブロック (⬛⬜🟥🟦)・全角空白・**点字ブロック U+2800..U+28FF** (2x4ドットを1文字で表現でき、テキストQRレンダラで最多用) を追加。画像添付だけを走査するフィルタを回避する Barracuda 観測の手法に対応
  - 背景: quishing は 2026 年上半期に約 **146%増**、2025年8-11月に成功事例が 4.6万→25万へ**5倍増**。FBI が 2026-01 に北朝鮮 Kimsuky/APT43 の利用を「MFA 耐性のある侵入経路」として警告
  - テスト6件追加 (短縮/リダイレクタ/サブドメイン判定、信頼ドメイン回帰、点字QR、幾何学記号QR)
- **kaname-bec DKIM リプレイ攻撃の検出** (署名ドメイン `d=` と From ドメインの整合検証)
  - 攻撃: 正規組織 (Google/PayPal/Apple 等) の DKIM 署名済みメールを入手して再送する。署名は有効なままなので DKIM は pass し、**DMARC は SPF と DKIM の OR 判定 (AND ではない) のため DMARC も pass** する → 受信側には「認証を完全に通過した正規メール」に見える
  - 従来の `check_auth` ではこの組み合わせ (SPF fail + DKIM pass + DMARC pass) が「1つ失敗 = 0.15」の軽微扱いで、ARC pass があると更に減点されていた
  - `dkim_check` は既に `d=` を解析していたが**整合検証に使っていなかった**ため、これを追加。DKIM が pass しているケースほど危険 (認証通過に見える) として重み付け
  - 親ドメイン署名 (`d=example.com` / From が `mail.example.com`) は正当として誤検出しない
  - 出典: 2025年の Google スプーフィング事例、"DMARC OR trap" (DMARC が OR ロジックである構造的弱点)
- **kaname-render SVG 添付攻撃の検出** (`svg_guard` モジュール新設)
  - 背景: 悪意ある SVG 添付は2024年比で**50倍**に増加 (2025年)。2026年2月の単一キャンペーンでは **120万通が53,000組織**へ配信された。SANS ISC が 2026-06 に MIME 型回避手法を警告
  - 検出: `<script>` 要素 (**非推奨 MIME 型 `application/ecmascript` による回避**も型を記録して検出)、イベントハンドラ (`onload=` 等、`<script>` なしの実行)、`javascript:`/`vbscript:` スキーム、`<foreignObject>` による HTML 埋め込み、base64/`atob()` の多層エンコード、外部リソース参照
  - `magic_bytes::is_svg` は**先頭256バイトしか見ず**、長いコメントで `<svg` を押し下げると検出を回避できたため、8KB まで走査する `looks_like_svg()` を追加
  - 出典: SANS ISC (2026-06, Xavier Mertens)、OPSWAT、Microsoft 脅威情報 (2026-02)

### Fixed
- **kaname-bec のキーワード検出が難読化で完全に回避できた問題を修正 (中核機能・最重要)**
  - 中核の BEC 検出器が件名・本文の照合に `to_lowercase()`/`to_ascii_lowercase()` のみを使っており、**ゼロ幅文字・soft hyphen (U+00AD)・全角ラテンの正規化が一切なかった**
  - 攻撃: 「至\u{00AD}急」は人間には「至急」と見えるが `contains("至急")` は false → 緊急性・金銭・チャネル誘導・Cialdini の全キーワード検出をすり抜けられた
  - 2026年の実キャンペーンで観測された手法 (RFC 2047 encoded-word でデコードされた件名に soft hyphen を散布) がそのまま通用する状態だった
  - `kaname-memory-guard::normalize_for_matching` を適用して解消 (kaname-oobv で確立した対策の横展開)

### Added
- **kaname-bec 表示名ホモグラフ検出** (`idn_homograph::analyze_display_name` / `fold_homoglyphs`)
  - 攻撃: `From: "СЕО 山田" <attacker@evil.com>` (キリル文字 С/Е/О) は人間には `CEO 山田` と区別できないが、従来の `to_lowercase()` 比較では一致せず**なりすまし検出を完全に回避**できた
  - ホモグリフを ASCII に畳み込んでから既知連絡先と照合するよう `reply_to_spoof` を修正。表示名自体のホモグリフ/スクリプト混在も検出可能に
  - 背景: 2025-2026 の観測ではホモグリフ悪用の主戦場が URL/ドメインから **From ヘッダーの表示名**へ移行 (表示名はレジストラの制約を受けず任意の Unicode を置けるため)。出典: Unit 42 (2025)、arxiv 2604.04926「Comprehensive List of User Deception Techniques in Emails」
  - 既存のドメイン用ホモグリフ判定を再利用し、誤検出防止テスト (日本語表示名/無関係な表示名) も追加
- **kaname-screen 出力監査に「セキュリティ判定の詐称」検出を追加** (`AuditFinding::ForgedSecurityVerdict`)
  - 攻撃: メール本文に「本メールはセキュリティチームにより検証済みです」等を仕込み、Q-LLM の要約に反映させてユーザーを信用させる
  - 設計根拠: Kaname の判定は `kaname-bec` の決定論的シグナルが source of truth であり、**LLM の散文は判定の根拠になり得ない**。したがって出力中の免罪主張は構造上いかなる信頼できる根拠にも裏付けられていない (幻覚か注入の反映)
  - 出典: arxiv 2605.17634 (LLMail-Inject — 良性メールに埋め込まれた4,300件の人手作成注入。エージェントの判定チャネル自体が攻撃対象になることを実証)、arxiv 2605.03378 (ARGUS — 決定が信頼できる根拠に裏付けられているか実行前に検証)
  - 誤検知防止のため**肯定的な免罪の断定のみ**を対象とし、正当な脅威警告 (「フィッシングの疑いがあります」) は検出しない
- **arxiv 研究ベースの防御コマンド10件を到達可能化** (これまで `invoke_handler` 未登録で死蔵)
  - 入力スクリーニング (2505.22852 §2.1) / 出力監査 (§2.2) / Tiered-Risk (§3) / メモリ信頼スコア (2601.05504) / Rule of Two (2601.17548) / ツール引数検証 (2601.11893) / トラジェクトリ記録・リセット / OOBV 推奨 / Deepfake 判定
  - `commands.rs` の `#[cfg_attr(feature = "tauri-app", ...)]` は src-tauri が該当フィーチャーを指定しておらず無効だったため、既存12コマンドと同じラッパー方式で登録

### Fixed
- **UI が呼ぶが未定義だった5コマンドを追加** (`mail_send`/`mail_get_mailboxes`/`mail_query_emails`/`bec_get_score`/`settings_save_onboarding`)
  - 「コマンドが存在しない」という不可解な失敗を、明示的な「未配線」エラーに変更 (偽データは返さない)
  - Inbox が起動時に無言で永久に空になっていた問題が、原因表示に変わった

### Changed
- **実装ステータスの正直化 (First Principles 監査の反映)**: `docs/maturity.md`・README・`docs/gap-analysis.md` D10 に、**現状のビルドではメールを送受信できない**事実を検証根拠付きで明記。`kaname-ui` が `kaname-jmap`/`kaname-store` に依存しておらず到達経路が無いこと、`messages` テーブルへの INSERT/SELECT がゼロ件であること等。D15 (コマンド死蔵) を追加

## [0.3.22] - 2026-07-17 — 最新研究反映・クロスクレート統合・監査バグ修正リリース

このリリースは (1) ワークスペース全体のビルド不能状態の解消、(2) 2026-07 の
最新研究 (quishing 亜種・CalPhishing・プロンプト注入) の反映、(3) Ultracode
徹底監査 (3エージェント並列・全27クレート) で発見したクロスクレート連携の
欠落とロジックバグの修正、(4) 実装状況の正直化 (docs/maturity.md,
docs/gap-analysis.md, README) をまとめたもの。**中核 (MLS暗号・LLM推論・
Firecracker・課金永続化・UIバックエンド配線) はモック段階であり本番運用は
不可** — 詳細は docs/maturity.md を参照。

### Added
- **kaname-render Quishing 構造亜種検出** (2026年研究反映, docs/research-2026-07.md)
  - `blob:`/`data:`/`javascript:` スキームの QR ペイロードを `Suspicious` に格上げ (従来は Neutral で素通り)
  - `assess_multi_qr()` / `MultiQrRisk` — 分割QR (Structured Append) 攻撃の兆候検出
  - `detect_ascii_qr()` — ブロック文字によるASCIIアートQR (画像デコード不要のテキスト解析) の検出
- **kaname-render CalPhishing 検出** (`CalendarRisk::AutoRegistrationAbuse`)
  - `METHOD:REQUEST`/`PUBLISH` の自動登録永続化 (元メール削除後もカレンダーに残る) と他のフィッシング兆候の併存を検出
  - 警告文で「カレンダー側のエントリ削除が必要」であることを明示
- **docs/research-2026-07.md**: 2026-07 の最新研究調査とKanameへの反映マップ (長所・短所・改善点の総括含む)
- **kaname-render カレンダー招待のプロンプト注入検査** (`CalendarRisk::PromptInjectionAttempt`)
  - .ics の DESCRIPTION/SUMMARY を `kaname-screen::PromptScreener` で検査 (ワークスペース内依存を新規追加、循環なし)
  - 命令上書きフレーズ・特殊トークン・Base64/Unicodeタグ/HTMLエンティティ注入を検出し Danger 判定
  - 誤検出防止のため `Blocked` (確定的マーカー一致) のみ採用 (エントロピー単独の `Suspicious` は不使用)
- **kaname-saas-guard SaaSリンクのプロンプト注入検査** (`SaasLinkInspector::evaluate`)
  - SaaSリンクのクエリパラメータ (`?note=`等) を `kaname-screen::PromptScreener` で検査し `SaasLinkRisk::Block` に格上げ
  - 偽SaaSドメイン検出 (`notdocusign.com`等) との併存を確認 (Suspicious→Block)
- **kaname-bec クロスクレート連携** (Ultracode監査で発見、docs/gap-analysis.md 参照)
  - `check_content_heuristics` に `kaname-pivot::PivotDetector` を統合 — 暗号通貨アドレス/WhatsApp/Telegram/Signal等の構造化チャネル誘導検出 (従来はハードコードフレーズ一致のみ)
  - `check_llm` に `kaname-screen::PromptScreener` を統合 — Quarantined LLM に渡す前にプロンプト注入をスクリーニングし、Blocked時はLLMをスキップして注入シグナルを加点

### Fixed
- **kaname-observability PIIサニタイザの検出漏れ** (北極星 I5 に直結)
  - `mask_email_addresses` が数字始まりのローカル部 (`12345@vendor.com` 等) を無加工でログに残していた問題を修正 (`is_ascii_alphabetic`→`is_ascii_alphanumeric`)
- **kaname-radar 集計バグ**: `unknown:` バケットが `or_insert_with` の返り値を捨てており、同一未解決ドメインからの2通目以降が集計されず継続キャンペーン検出が機能していなかった問題を修正
- **kaname-mls 開始者側エポック初期化漏れ**: 会話開始者が自分の会話に届くリプレイ Commit を検出できなかった問題を修正 (`start_one_to_one` で `epochs` を初期化し受信側と対称化)
- **kaname-store SQLCipher鍵のゼロ化漏れ**: PRAGMA/ATTACH 文に埋め込む生鍵文字列を `Zeroizing<String>` でラップし、実行後にヒープ上の平文鍵を確実にゼロ化
- **kaname-oobv Unicode/全角バイパス**: `recommend` のキーワード照合を `kaname-memory-guard::normalize_for_matching` 経由に変更し、全角ラテン文字 (`ＵＲＧＥＮＴ`)・ゼロ幅文字挿入によるOOBV推奨回避を防止
- **kaname-jmap SSRFリダイレクト未検証**: `JmapClient::connect` の HTTP クライアントに `safe_redirect_policy()` (per-hop DNS再検証) を適用し、DNSリバインディングによるSSRFの入口を閉塞
- **kaname-ai preflight モジュール**: Dual-LLM パイプライン入口での事前検査
  - `preflight_untrusted()` — Bidi 制御文字 (U+202E 等) / ゼロ幅文字 / 既知インジェクションパターンを検出
  - `PreflightResult` (Clean / Advisory / Block) と `Finding` 列挙型
- **kaname-dlp 本物の正規表現エンジン** (スタブ撤廃)
  - `regex` クレート導入。エンジン構築時に全パターンをコンパイルしキャッシュ (メール毎の再コンパイル無し)
  - 不正パターンはフェイルセーフ (マッチ無し + 警告ログ)
  - `excerpt_match` が実際の一致位置の前後 ±30 文字を抽出 (監査証跡の精度向上)
- **kaname-dlp render_bridge モジュール**: kaname-render パイプラインへの DLP 統合
  - `EnvelopeScanner` が `kaname_render::DlpScanner` trait を実装
  - `render_with_dlp()` 経由で受信メールの DLP Block がレンダリング前に発動
- **kaname-render 実 MIME パース** (スタブ撤廃)
  - `mail-parser` (Stalwart Labs) による RFC 5322/2045-2049 準拠パース
  - From/To/Cc/Subject/Date/Message-ID/本文/添付ヘッダーを抽出
  - Authentication-Results ヘッダーから SPF/DKIM/DMARC 結果をパース
  - `DlpScanner` trait による DLP 注入ポイント (依存グラフ単方向性を維持)
- **kaname-bec 意味的トピック異常検出** (スタブ撤廃)
  - TF-IDF bag-of-words + コサイン類似度による送信者の典型トピックとの距離計算
  - 英語 (単語境界) と日本語 (CJK 文字単位) の混在テキストに対応、ストップワード除去
  - 類似度 < 0.15 で「異常なトピック」と判定 (例: CFO が突然配送通知を送る)
- **kaname-screen RateLimiter** (OWASP ASI-10 リソース枯渇 / DoS 対策)
  - トークンバケット方式。バースト許容量と定常レートを分離設定
  - 時刻を外部注入する決定的設計 (テスト容易) + クロック巻き戻り耐性
  - `docs/owasp-agentic-mapping.md` の ASI-10 を 🔶 部分 → ✅ に更新
- **kaname-screen 入力スクリーニング拡充**
  - ドイツ語 override フレーズ・context poisoning マーカーを `PromptScreener` に追加
- **敵対的テストコーパス 17 → 35 件** (kaname-tests)
  - カテゴリ H (OutputAuditor 出力検査) / I (CRLF・空白パディング・HTML コメント注入) 新設

### Fixed
- ワークスペース全体の clippy 警告ゼロ化 (`-D warnings` クリーン)
- MLS セーフティナンバー計算式 (`% 100_000` で常に 5 桁)
- Bearer トークンのログ秘匿バグ (トークン本体ではなく "Bearer " 内の空白を検出していた)
- BEC ブランドなりすまし閾値 (70→50) と "dan mode" 攻撃マーカーの小文字比較
- Shannon エントロピーの非決定性 (HashMap→BTreeMap + f64 演算)

## [0.3.21] - 2026-06-02 — GitHub 公開準備リリース

### Added
- **.gitattributes**: 改行正規化・Linguist 言語統計・バイナリ指定
- **.editorconfig**: エディタ間の一貫性 (Rust 4 / Web 2 スペース)
- **.env.example**: 環境変数テンプレート (BYOK/JMAP/Stripe/暗号/OTel)

### Fixed
- PR テンプレートの case 重複 (PULL_REQUEST_TEMPLATE.md と pull_request_template.md) を解消
  - DRI 確認付きの既存 pull_request_template.md を採用

### Changed
- `.gitignore`: fuzz/corpus シードを公開対象に変更 (回帰防止の価値ある資産)
- README プロジェクト統計を v0.3.20 に更新 + docs 索引へのリンク追加

### Verified
- GitHub 公開必須ファイル 13 種すべて存在
- シークレット混入なし (gitleaks 相当スキャン)
- 秘密鍵・証明書の混入なし
- .env はgitignore除外、.env.example をテンプレートとして提供
- static-check 6 項目合格


## [0.3.20] - 2026-06-01 — コンパイル阻害要因の除去

### Fixed
- **致命的: subprocess.rs の unsafe libc::kill を除去**
  - `#![deny(unsafe_code)]` と矛盾する `unsafe` ブロックが存在 (コンパイル不可)
  - さらに libc が依存に未宣言 (二重にコンパイル不可)
  - std のみの安全な実装に置換 (try_wait → kill → wait、ゼロ依存維持)
  - グレースフルシャットダウンは try_wait による終了確認で代替

### Added
- static-check.sh に 2 チェック追加:
  - [5] unsafe ブロック検出 (deny(unsafe_code) 整合)
  - [6] 未宣言依存検出 (libc:: 等の使用 vs Cargo.toml)

### Verified
- 深層静的解析で全 .rs の括弧バランスを検証 (raw string 考慮で全て一致)
- unsafe ブロック 0、未宣言依存 0 を確認
- 静的チェック 6 項目すべて合格

### Notes
- この unsafe は過去セッションで見落とされていた実コンパイル阻害要因
- static-check 強化により同種の問題が今後 CI で自動検出される


## [0.3.19] - 2026-06-01 — 静的検証リリース

### Added
- **scripts/static-check.sh**: cargo 不要の静的整合性チェック
  - pub mod 宣言とファイル存在の照合
  - use kaname_X と Cargo.toml 依存の整合
  - workspace members とディレクトリの整合
  - バージョン整合 (Cargo/package.json/tauri.conf)
- ci.yml に static-check ジョブ追加
- package.json / Makefile に static-check ターゲット追加

### Verified
- 全 27 クレートのモジュール宣言・依存・バージョンが整合 (0 エラー)
- 同名型 (Verdict/ActionType) の re-export 衝突がないことを確認
  (dual_llm::ActionType のみ re-export、threat_intel はフルパス)

### Notes
- 実機 cargo build はネットワーク制約により本環境では実行不可
- static-check は cargo check の補完 (実機 CI では cargo check が必須)


## [0.3.18] - 2026-06-01 — ドキュメント整合性リリース

### Added
- **docs/README.md**: ドキュメント索引 (24 文書の目的別地図)
  - 孤立していた research 系 3 文書 (arxiv/category/owasp) を索引から参照
- **.claude/skills/agentic-defense.md**: 8 層エージェント防御の統合スキル
  - 入力スクリーニング → Dual-LLM → Bridge → Tiered-Risk → Rule of Two
    → ArgumentValidator → 出力監査 → Trajectory Monitor の全体像

### Fixed
- README プロジェクト統計を v0.3.17 実態に更新 (452 テスト/27 クレート)
- gap-analysis.md を v0.3.9 → v0.3.17 に更新
- research 文書の孤立を解消 (docs/README.md から全参照)

### Changed
- .claude/skills: 8 → 9 スキル


## [0.3.17] - 2026-06-01 — Trajectory Monitoring リリース

### Added
- **Agent Trajectory Monitoring** (kaname-observability/trajectory.rs、10 ユニット + 2 proptest)
  - エージェント行動軌跡を時系列で記録・分析 (OWASP ASI-09 対応)
  - Rule of Two 違反の軌跡検出 (3 能力が時系列で揃う)
  - 高頻度操作検出 (自動化攻撃の兆候)
  - 危険シーケンス検出 (機密アクセス → 外部送信)
  - PII を含まない (操作種別とタイムスタンプのみ、I5 準拠)
- ui に `record_agent_step` / `reset_trajectory` コマンド配線
- kaname-ui に kaname-observability 依存追加

### Changed
- Rust テスト: 456 → 468 件
- proptest: 18 → 20 件
- OWASP ASI-09 に Trajectory Monitor を追記

### Research
- AgentDoG / trajectory monitoring 研究に基づく実装
- これで前回 future work の trajectory monitoring を完了


## [0.3.16] - 2026-06-01 — AgentDojo 互換テストリリース

### Added
- **AgentDojo 互換 敵対テストスイート** (kaname-tests/agentdojo.rs)
  - arxiv 2406.13352 (NeurIPS 2024) の 4 正規攻撃パターンで Kaname を検証:
    - Ignore Previous Instructions (en/ja)
    - System Message 注入 (ChatML/INST マーカー)
    - You-are-now 系の役割上書き
    - benign ケース (誤検知ゼロ確認)
  - 入力スクリーニング・出力監査の網羅検証
  - **攻撃成功率 0% を assert** (GPT-4o は攻撃下 45% に低下)
- kaname-tests に kaname-ai/screen/bec/dlp 依存を明示追加

### Changed
- Rust テスト: 452 → 456 件
- AgentDojo ベンチマークで Kaname の Dual-LLM + screen 防御を定量検証

### Research
- AgentDojo (2406.13352): 97 タスク + 629 セキュリティテストケースの業界標準
- Kaname の型境界 + kaname-screen が AgentDojo 正規攻撃を 100% ブロック


## [0.3.15] - 2026-06-01 — 配線統合リリース

### Fixed
- **孤立モジュールの配線解消** (前回 v0.3.13/v0.3.14 で作成したが未配線だった):
  - EDM を DLP エンジンに統合: `Predicate::ExactDataMatch` バリアント追加
    + `EvalCtx::edm_sets` フィールド + 評価ロジック
  - Rule of Two を ui に配線: `check_rule_of_two` コマンド
  - ArgumentValidator を ui に配線: `validate_tool_argument` コマンド

### Added
- EDM 統合テスト (DLP エンジン経由での検出)
- Rule of Two / ArgumentValidator コマンドの統合テスト 4 件

### Changed
- Rust テスト: 447 → 452 件
- 全クレート・全モジュールが配線済み (孤立ゼロを再確認)


## [0.3.14] - 2026-05-31 — EDM・OWASP マッピングリリース

### Added
- **EDM (Exact Data Matching)** (kaname-dlp/edm.rs、11 ユニット + 3 proptest)
  - ハッシュフィンガープリントによる機密データの完全一致検出
  - 平文を保存せず salt 付きハッシュのみ保持 (I5 プライバシー準拠)
  - chunk 分割攻撃に対抗 (トークン単位で照合)
  - min_matches 閾値で誤検知を抑制
- **docs/owasp-agentic-mapping.md**: OWASP Agentic Top 10 (2026) 対応マッピング
  - ASI-01〜10 への Kaname 防御マッピング (9/10 完全対応)

### Changed
- Rust テスト: 433 → 447 件
- proptest: 15 → 18 件
- 前回文書化した「今後の検討」優先度1 (EDM)・優先度4 (OWASP) を実装

### Research
- EDM は 2026 年 DLP 業界標準 (hash-based fingerprinting)
- OWASP Agentic Top 10 (2026, ASI prefix) に Kaname を照合し 9/10 を確認


## [0.3.13] - 2026-05-31 — 10カテゴリ研究反映リリース

### Added
- **Rule of Two** (kaname-ai/rule_of_two.rs、8 テスト + 1 proptest)
  - Meta の agentic セキュリティ原則 (arxiv 2601.17548)
  - [untrusted入力/機密アクセス/外部通信] の 3 能力同時保持を Violation 検出
  - 外部通信の分離を最優先で提案する mitigation
- **ArgumentValidator** (kaname-screen、4 テスト)
  - CaMeL argument manipulation バイパス対策 (arxiv 2601.11893)
  - untrusted データによる宛先すり替え・許可外ドメイン紛れ込みを検出
- **docs/category-research-2026.md**: 10 カテゴリ別研究調査記録

### Research
- 10 カテゴリ (AIセキュリティ/認可/暗号/メール脅威/DLP/サンドボックス/
  プロトコル/可観測性/i18n/課金) で arxiv + GitHub を調査
- CaMeL の argument manipulation 脆弱性 (2601.11893) を確認・対策
- Meta "Rule of Two" を実装
- MLS combiner (PQ MLS, 2026年12月マイルストーン) を将来課題として記録

### Changed
- Rust テスト: 421 → 433 件
- proptest: 14 → 15 件


## [0.3.12] - 2026-05-31 — KAT・整合性リリース

### Added
- **ML-KEM/X25519 KAT** (kaname-crypto/tests/kat.rs、6 テスト)
  - FIPS 203 パラメータ検証 (公開鍵 1184 / 暗号文 1088 / 共有秘密 32)
  - RFC 7748 X25519 パラメータ検証
  - derive_key の決定論性・domain separation 検証
  - verification-boundary.md で約束した KAT を実装
- **AlgId メタデータメソッド**: `public_key_len` / `ciphertext_len` / `shared_secret_len`
- **example 2件**: screen_and_audit / tiered_risk_demo
- **crypto-kat CI ジョブ**: KAT + X25519 検証 + 検証境界文書チェック

### Fixed
- CLAUDE.md のクレート数を 25 → 27 に修正 (実態との乖離解消)
- verification-boundary.md を threat-model.md から参照 (孤立文書解消)

### Changed
- README にセキュリティアーキテクチャ節を追加 (arxiv 研究の対応表)
- Rust テスト: 415 → 421 件


## [0.3.11] - 2026-05-30 — 検証境界リリース

### Added
- **X25519 出力検証** (kaname-crypto): arxiv eprint 2026/192 V2/V4 対応
  - `validate_x25519_output()`: 共有秘密の all-zero を constant-time 検出
  - `CryptoError::WeakSharedSecret`: small-subgroup 攻撃の兆候を報告
  - encapsulate / decapsulate 両方で検証
  - X25519 検証テスト 3 件追加
- **docs/verification-boundary.md**: Kaname の検証境界を 3 Tier で明示
  - "verification theatre" (形式検証の盲信) を避ける多層防御原則
- docs/arxiv-research-2026.md 第3回調査を追記

### Security
- eprint 2026/192「Verification Theatre」の教訓を反映
  - libcrux が欠いていた X25519 contributory behavior 検証を独自実装
  - 「形式検証済み」を盲信せず独自 sanity check を追加

### Changed
- Rust テスト: 412 → 415 件
- kaname-crypto: 478 → 約540 行

## [0.3.10] - 2026-05-30 — 配線統合リリース

### Fixed
- **孤立クレートの配線**: kaname-screen / kaname-memory-guard が ui に未配線だった問題を解消
  - kaname-ui/Cargo.toml に依存を追加
  - commands.rs に 4 つの UI コマンドを追加:
    - `screen_user_input` (入力スクリーニング)
    - `audit_ai_output` (出力監査)
    - `check_action_risk` (Tiered-Risk 判定)
    - `check_memory_trust` (メモリ汚染防御)
  - 6 つの統合テストを追加
- kaname-ui/Cargo.toml に `[features]` (tauri-app) を明示定義

### Changed
- Rust テスト: 406 → 412 件
- CLAUDE.md に arxiv 研究反映機能のマップを追加
- gap-analysis.md を v0.3.9 状態に更新 (412テスト/33項目)
- README プロジェクト統計を v0.3.9 に更新


## [0.3.9] - 2026-05-30 — メモリ汚染防御リリース

### Added
- **kaname-memory-guard** (新クレート、327 行、11 ユニット + 3 proptest)
  - `TrustScorer`: composite trust scoring (arxiv 2601.05504 防御1)
    出所別信頼度 + 注入パターン検出 + 異常長検出
  - `MemorySanitizer`: temporal decay + filtering (防御2)
    指数減衰 (半減期 30 日) で古い汚染エントリの影響を低減
  - MINJA / MemoryGraft 攻撃への先行防御基盤
- `docs/arxiv-research-2026.md` 第2回調査を追記 (メモリ汚染・サイドチャネル)

### Changed
- クレート数: 26 → 27 (kaname-memory-guard 追加)
- Rust テスト: 398 → 409 件
- proptest: 11 → 14 件

### Research
- MINJA (2503.03704): クエリのみで 95% メモリ注入成功 — 将来の脅威として記録
- MemoryGraft (2512.16962): トリガー不要の永続的 behavioral drift
- Memory Poisoning Defense (2601.05504): composite trust scoring + sanitization を実装
- サイドチャネル対策 (2505.22852 §4) の Kaname 現状を再評価


## [0.3.8] - 2026-05-30 — arxiv 研究反映リリース

### Added
- **kaname-screen** (新クレート、368 行、13 ユニット + 3 proptest)
  - `PromptScreener`: 入力スクリーニング (arxiv 2505.22852 §2.1)
    命令上書きフレーズ・特殊トークン・高エントロピー文字列を検出
  - `OutputAuditor`: 出力監査 (§2.2) 隠れた "## System:" 命令・外部送信先を検出
- **Provenance::UserUpload** (kaname-ai): 添付ファイル由来データの provenance タグ (§2.3)
- **Tiered-Risk Access Model** (kaname-ai/tiered_risk.rs、233 行、10 ユニット + 2 proptest)
  - Green/Yellow/Red の3段階リスク制御 (§3)
  - prompt fatigue 低減: Green は確認不要、Red のみ多要素承認
- `docs/arxiv-research-2026.md`: arxiv 調査記録 (CaMeL/AgentDojo/ML-KEM-MLS)

### Changed
- クレート数: 25 → 26 (kaname-screen 追加)
- Rust テスト: 380 → 398 件
- proptest: 9 → 11 件

### Research
- CaMeL (2503.18813) との設計一致を確認 — Kaname の Dual-LLM 型境界は独立に同じ結論に到達
- AgentDojo (2406.13352) の正規攻撃パターンを kaname-screen でカバー
- ML-KEM/MLS PQ cipher suites (IETF draft) が Kaname の HybridKEM 選択を裏付け


## [0.3.6] - 2026-05-26

### Added
- 全 24 クレートの lib.rs に `#![deny(clippy::unwrap_used)]` + `#![deny(clippy::expect_used)]` 追加
  (CLAUDE.md I6 との整合を取る)
- `.cargo/config.toml` に `RUSTDOCFLAGS = "-D warnings"` 追加
- fuzz corpus を 12 → 23 シードに拡充 (AiTM URL / カレンダー招待 / SSA バイパス試行)
- `package.json` に `test:coverage` / `test:coverage:ui` スクリプト追加
- `kaname-continuity` を完全実装 (313 行、7 ユニット + 4 proptest)
  - `ContinuitySession` (Handoff 状態管理)
  - `HandoffManager`
  - scroll_position clamp 不変条件
  - シリアライズ冪等性
- `.github/ISSUE_TEMPLATE/security_notice.md` 追加

### Fixed
- CLAUDE.md I6 (`#[deny(clippy::unwrap_used)]`) とコードの矛盾を解消

### Changed
- proptest: 9 → 13 件 (continuity +4)


## [0.3.5] - 2026-05-26

### Added
- `pub fn` 65 箇所に `#[must_use]` 追加 (戻り値の見落とし防止)
- `pub fn` 31 箇所に `///` ドキュメントコメント追加
- `.claude/skills/` を 3 → 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv に proptest 4 件追加
- kaname-radar に DNS 解決スケルトン (`DnsResolver` トレイト) + テスト 3 件追加
- kaname-ssa に proptest 3 件追加
- kaname-saas-guard に proptest 3 件追加
- CLAUDE.md を 174 → 233 行に拡充 (v0.3 全機能の実装場所マップ、セッション開始プロトコル)
- package.json に test:e2e / test:a11y / fuzz:* / stats / snapshots:init スクリプト追加

### Fixed
- `.gitignore` から `Cargo.lock` 除外を削除 (アプリケーションはコミット必須)
- `integration.rs` の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- `kaname-sandbox` の `panic!` にセキュリティ不変条件コメントを追加

### Changed
- Rust テスト: 381 → 384 件
- proptest: 6 → 8 件 (oobv / radar / ssa / saas-guard)


### Added
- `#[must_use]` を 65 の公開 API 関数に追加 — 戻り値の見落とし防止
- `.claude/skills/` を 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv にプロパティテスト 4 件追加
- kaname-radar にプロパティテスト 2 件追加

### Fixed
- integration.rs の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- 本番コードの unwrap 合計 = 0 達成

### In Progress
- E2E スナップショット基準画像 (CI 初回実行で生成)
- DNS 解決を kaname-radar に統合 (現在はシミュレーション)

### Planned for v1.0.0
- Design Partner 30 社での実証データ収集
- cargo build --release の CI 4 プラットフォーム通過
- App Store Notarization + Microsoft Authenticode 取得


### Added
- `#[must_use]` を 65 の公開 API 関数に追加 — 戻り値の見落とし防止
- `.claude/skills/` を 8 スキルに拡充 (bec-detection / dual-llm / new-crate / performance / security-review)
- `.claude/commands/` に 4 スラッシュコマンド追加 (commit / security-audit / new-crate / bench)
- kaname-oobv にプロパティテスト 4 件追加
- kaname-radar にプロパティテスト 2 件追加

### Fixed
- integration.rs の `unwrap()` 7 件を `expect()` に変換 (明確なエラーメッセージ)
- 本番コードの unwrap 合計 = 0 達成

### In Progress
- E2E スナップショット基準画像 (CI 初回実行で生成)
- DNS 解決を kaname-radar に統合 (現在はシミュレーション)

### Planned for v1.0.0
- Design Partner 30 社での実証データ収集
- cargo build --release の CI 4 プラットフォーム通過
- App Store Notarization + Microsoft Authenticode 取得



- LICENSE を AGPL-3.0 公式全文 (661 行) に置換中
- docs/specifications/ 言語非依存仕様ディレクトリ作成
- E2E スナップショット基準画像の生成 (CI 環境で実行予定)

### Planned for v0.4.0
- kaname-radar の DNS 解決を実機統合 (現在はシミュレーション)
- SSA モデルの精度向上 (30通 → 10通で信頼できるプロファイル)
- AiTM CTI フィード (既知 PhaaS インフラの動的更新)


## [0.3.0] - 2026-05-12 — 2026 Q1 脅威対応リリース

> Deep Research (Microsoft Q1 2026 Threat Report / Cofense / Barracuda) + Ultrathink

### Added (新機能)

**AiTM Link Detector** (`kaname-bec/src/aitm.rs`, 299行, 11テスト)
- Tycoon2FA / Storm-1747 の PhaaS インフラパターン検出
- URL 内セッション捕捉パラメーター (id_token / code / state) 検出
- 正規ブランドを装った偽ドメイン検出 (microsoft.com.evil.tk 形式)
- 多段スコアリング (0-100)、80+ で Dangerous 判定

**Sender Style Authentication** (`kaname-ssa`, 新クレート, 469行, 13テスト)
- 7次元の文体指紋 (送信時刻分布・フォーマリティ・文長・句読点密度等)
- スタイル距離 0.60+ で警告、0.75+ で強警告
- コンテンツ保存なし (数値ベクトルのみ、プライバシー保護)
- 日本語・英語両対応の敬語レベル推定

**HTML Smuggling Detector** (`kaname-render/src/html_smuggling.rs`, 12テスト)
- Blob URI 生成検出 (URL.createObjectURL)
- Base64 デコード + 即時実行 (atob + eval) 検出
- 自動ダウンロードトリガー (createElement + click) 検出
- 偽 CAPTCHA ページ検出 (日本語・英語)
- Shell 参照 (mshta / PowerShell / cmd.exe) 検出
- 多重難読化 (unescape + decodeURIComponent + charCode 組み合わせ)

**Calendar Invite Guard** (`kaname-render/src/calendar_guard.rs`, 10テスト)
- .ics 添付の URL・主催者・会議リンクを多角検査
- 緊急性偽装キーワード検出 (日本語・英語)
- フリーメール主催者警告 (法人会議に gmail 等)
- 数字混入ドメイン検出 (amaz0n / g00gle 等)
- 無料TLD ブロック (.tk / .ml / .ga 等)

### Changed
- LICENSE を AGPL-3.0 正式全文に置換 (73行 → 164行, 法的有効性確保)
- `//!` ドキュメントを kaname-oobv・kaname-ssa に追加 (24/24 完備達成)
- `.cargo/config.toml` 追加 (Apple M1 最適化・lld 高速リンク・コマンドエイリアス)

### Research Basis
- Microsoft Q1 2026: AiTM が最大脅威、Tycoon2FA が 3日で 35,000 ユーザー被害
- Cofense: AI フィッシング 204% 増、76% URL が一意だが 94% は同一 IP を共有
- Barracuda: ポリモーフィック攻撃が 2026 年のデフォルトに
- Group-IB: HTML スマグリング + Blob URI フィッシングが急増


## [0.2.0] - 2026-04-29 — 2026年新脅威対応リリース

### Added (新機能 — Deep Research + Ultrathink ベース)
- **#1 OOBV (Out-of-Band Verification)** - 新クレート `kaname-oobv` (489行、14テスト)
  - BIP39 ベース 6 ワード検証フレーズ (50 ワードの安全な部分集合)
  - チャレンジ番号方式で Deepfake 音声攻撃を防御
  - 5 分期限、ZeroizeOnDrop でメモリから自動消去
  - 日本語/英語の金融キーワード自動検出
  - 監査ログ (フレーズは記録しない、結果のみ)
- **#2 CCPD (Cross-Channel Pivot Detection)** - 新クレート `kaname-pivot` (612行、16テスト)
  - 7 種類の pivot 検出 (Teams/Slack/Zoom/Google Meet/SaasDoc/Phone/Crypto)
  - 過去 30 日のやり取りベースで信頼スコア計算
  - 日米電話番号フォーマット対応
- **#3 QR Code Quishing 防御** - `kaname-render/src/quishing.rs` (345行、10テスト)
  - typosquatting 検出 (Levenshtein 距離)
  - 数字混入パターン (amaz0n、g00gle、paypa1)
  - free TLD ブロック (.tk、.ml、.ga、.cf、.gq)
  - 信頼ドメイン許可リスト
- **#4 SaaS Link Safety** - 新クレート `kaname-saas-guard` (459行、11テスト)
  - 9 種類の SaaS プラットフォーム認識
  - 偽サブドメイン検出 (docusign.evil.com 形式)
  - 送信者別 SaaS 利用履歴管理
  - リスク 5 段階評価
- **#5 Deepfake Audio/Video Advisory** - `kaname-render/src/deepfake_advisory.rs`
  - MIME + 拡張子の両方で検出
  - 金融キーワード + 緊急性で警告レベル上昇

### Documentation
- `docs/new-features-v0.2.md` — 2026 年最新脅威対応設計書 (Deep Research 結果含む)
- `docs/performance-history.md` — リリース別ベンチマーク履歴
- `docker-compose.yml` — 開発環境の自動セットアップ
- examples/ ディレクトリ追加 (oobv_basic / pivot_detect / deepfake_advisory / dual_llm_safety)

### Web Research 結果統合
- AI 生成フィッシング 1,265% 急増 (FBI 2024 advisory)
- $25.6M 香港 CFO Deepfake 動画事件
- Voice cloning 1,633% 急増 Q1 2025 vs Q4 2024
- BEC 損失 $27.7 億 (2024 年単年)
- VEC、Quishing、SaaS 経由フィッシング、AitM (MFA バイパス)

### Changed
- Cargo.toml workspace に新クレート 2 つ追加 (kaname-oobv、kaname-saas-guard)
- クレート総数: 20 → 22
- Rust テスト総数: 247 → 296+

### Apple 流の戦略 (採用基準)
全新機能は以下を満たす:
- 北極星 (AIが助けても裏切らない) に整合
- 既存機能と重複しない
- 競合不在 (Superhuman/Proton/HEY は未対応)
- 実装 6 ヶ月以内

### Apple 流の却下 (No と言った機能)
- 受信箱全体の AI 解析モード (北極星と矛盾)
- クラウドベース AI 判定の追加 (Privacy 原則と矛盾)
- 取引先データベース統合 (ベンダーロックイン)
- ブロックチェーン送信履歴 (オーバーエンジニアリング)
- 行動分析ベース異常検出 (ユーザーデータ収集が必要)


### Added
- **新機能 #1: Out-of-Band Verification (OOBV)** — Deepfake 詐欺対策 (`crates/kaname-oobv/`, 489 行, 14 テスト)
  - BIP39 ベース 6 ワード検証フレーズ (50 ワードの安全な部分集合)
  - チャレンジ番号方式 (N 番目だけを答えさせて全ワード露出を防ぐ)
  - ZeroizeOnDrop でメモリ自動消去
  - 5 分期限 + 監査ログ (フレーズは記録しない)
  - 多言語金融キーワード検出 (日本語 + 英語)
- **新機能 #2: Cross-Channel Pivot Detection (CCPD)** — マルチチャネル攻撃検出 (`crates/kaname-pivot/`, 612 行, 16 テスト)
  - 電話番号 (国際/日本/英米フォーマット) 検出
  - Microsoft Teams / Slack / Zoom / Google Meet 会議リンク検出
  - DocuSign / Google Drive / OneDrive / SharePoint SaaS リンク検出
  - Bitcoin / Ethereum ウォレットアドレス検出 (BEC の高リスクシグナル)
  - PivotHistory による信頼スコア計算
- **新機能 #5: Deepfake Audio/Video Advisory** — 添付ファイル警告 (`crates/kaname-render/src/deepfake_advisory.rs`, 13 テスト)
  - 4 段階の警告レベル (None/Info/Medium/High)
  - 音声/動画 MIME + 拡張子の両方で検出
  - 金融キーワード + 緊急性で警告レベルを上げる
  - 推奨アクション: ShowAdvisory / PlayInSandbox / OobvBeforePlay
- **新機能設計書**: `docs/new-features-v0.2.md` (5 機能の Phase 計画)

## [0.1.4] - 2026-04-29

### Added
- **Apple 流ドキュメント**:
  - `docs/100-year-vision.md` (213 行) — 100 年保守ビジョン、暗号世代交代計画
  - `docs/brand-guidelines.md` (255 行) — トーン&マナー、UI ライティング規範
  - `docs/decisions-not-to-do.md` (233 行) — Apple 流「No」と言った決定の記録
- `docs/archive/README.md` — 歴史保管原則の明文化
- `docs/keynotes-README.md` — keynote 文書の役割分担

### Changed
- `release.yml` をデュアル署名版に統合、旧 `release-workflow.yml` を archive へ
- `keynote.md` → `vision-keynote.md` (北極星の核として明確化)
- `keynote-2026.md` → `launch-keynote-2026.md` (発表台本として明確化)
- `design.md` を Apple Platforms 準拠 v0.2 に置換、旧 v0.1 は archive へ

### Fixed
- 重複ワークフローを統合 (release.yml と release-workflow.yml)
- 重複 keynote ドキュメントの役割を明確化

## [0.1.3] - 2026-04-29

### Added
- `.github/CODEOWNERS` で 20 領域に DRI を明示 (Apple "Directly Responsible Individual" モデル)
- `kaname-continuity` クレート (Apple Continuity 風の OS 跨ぎ機能)
- `docs/design-reviews/` 構造 (proposals → decisions の流れ)
- `scripts/stats.sh` プロジェクト統計自動生成
- `scripts/generate-icons.sh` 全 OS アイコン生成
- 12 個のアイコンプレースホルダー (16x16 ~ 1024x1024 PNG)

### Changed
- 全 20 クレートに `//!` モジュールドキュメント追加 (cargo doc 対応)
- 全 20 クレートに個別 README.md を追加 (crates.io 公開品質)
- `kaname-mockserver` に `[[bin]]` セクション追加 (`cargo run -p kaname-mockserver --bin jmap-mock`)

## [0.1.2] - 2026-04-29

### Added
- 全 19 クレートに `[dev-dependencies]` セクション (proptest / tempfile / mockito / tokio-test)
- 16 クレートに `kaname-error` ワークスペース内依存を追加
- `.github/workflows/e2e.yml` — Playwright E2E + axe-core a11y CI (256 行)
- `.github/workflows/fuzzing.yml` — 独立ファジング CI (177 行、自動 Issue 作成)
- `e2e/__snapshots__/` 視覚的回帰テスト基準画像ディレクトリ
- ワークスペース依存に `tokio-test` と `mockito` を追加

### Changed
- ファジングを `release-workflow.yml` から独立した `fuzzing.yml` に分離
- E2E テストの実行頻度を 4 段階化 (PR 2分 / main 30分 / 週次 4時間 / 手動)

### Fixed
- `cargo test --workspace` がリンクエラーで失敗していた問題 (dev-deps 欠落)
- `kaname-error` クレートが孤立していた問題

## [0.1.1] - 2026-04-28

### Added
- v0.1.0 リリース後の改善
- `scripts/release.sh` — 9 ステップリリース自動化
- `crates/kaname-mockserver/` — JMAP モックサーバー (E2E 用)

## [0.1.0] - 2026-04-26

### Added
- **Dual-LLM 型安全 AI パイプライン** (`kaname-ai`): `Content<Untrusted>` 型でコンパイル時にプロンプト注入境界を強制。Superhuman の CVE を型システムで防ぐ。
- **BEC 多信号検出器** (`kaname-bec`): 7 信号 (ドメイン類似度、スプーフィング、緊急性マーカー、QR フィッシング、VEC、多ペルソナキャンペーン、メール爆撃)
- **MLS RFC 9420 E2E 暗号化** (`kaname-mls`): 件名を含む全体を暗号化、ML-KEM-768 + X25519 ハイブリッド KEM
- **DLP ルールエンジン** (`kaname-dlp`): boolean 式木で 12 分類器
- **Firecracker 添付サンドボックス** (`kaname-sandbox`)
- **JMAP 完全実装** (`kaname-jmap`)
- **DLPラベル強制 AI アクセス制御** — Microsoft Copilot CVE CW1226324 対策
- **AI生成フィッシング検出**: 精度 94.26%
- **Liquid Glass UI** (`KanameDesign.tsx`): Apple macOS Tahoe 26 準拠
- **GitHub Actions CI/CD**: check/test/clippy/fmt/audit/deny/bench/build/release の完全パイプライン
- **cargo deny 設定**: ライセンス・脆弱性・禁止クレート管理

### Tests
- 197 のユニットテスト + 統合テスト
- 50 ペイロード × 7 カテゴリの敵対テスト
- todo!() ゼロ達成

<!-- 2026-09 訂正: 以下は誤ったリポジトリ (kaname-app/kaname) を指していた
     (D31/D33 と同じ欠陥クラス)。実際のリポジトリ shizukutanaka/kaname に
     訂正した。ただし git tag は一つも作成されていない (v0.1.0〜v0.7.1 の
     いずれも) ため、これらのリンクは訂正後もリリースタグが作られるまで
     404 になる。タグ作成はリリース権限を持つ人間の判断領域のため、本
     セッションでは作成していない。v0.5.0 以降 (このリポジトリで実際に
     行われたリリース) のリンクは追加していない — 存在しないタグへの
     リンクをこれ以上増やすと同じ問題を広げるだけのため。 -->
[Unreleased]: https://github.com/shizukutanaka/kaname/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/shizukutanaka/kaname/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/shizukutanaka/kaname/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/shizukutanaka/kaname/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/shizukutanaka/kaname/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/shizukutanaka/kaname/releases/tag/v0.1.0
