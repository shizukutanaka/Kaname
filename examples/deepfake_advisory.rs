//! Deepfake Audio/Video Advisory の使用例
//!
//! 音声・動画添付ファイルに対する警告判定の動作を確認する。

fn main() {
    println!("=== Deepfake Advisory Example ===\n");

    let cases = vec![
        ("audio.mp3", "audio/mpeg", "至急振込をお願いします。音声で説明しました。", "HIGH"),
        ("meeting.mp4", "video/mp4", "会議の録画を共有します。", "MEDIUM"),
        ("report.pdf", "application/pdf", "月次報告書です。", "NONE"),
        ("voice.wav", "audio/wav", "通常のメッセージです。", "MEDIUM"),
    ];

    for (filename, mime, body, expected) in &cases {
        println!("ファイル: {filename} ({mime})");
        println!("本文: {body}");
        println!("期待される警告: {expected}");

        let has_audio = mime.starts_with("audio/");
        let has_video = mime.starts_with("video/");
        let financial = ["振込", "支払", "wire transfer", "payment"]
            .iter().any(|kw| body.contains(kw));
        let urgent = ["至急", "urgent", "immediately"]
            .iter().any(|kw| body.contains(kw));

        let level = if (has_audio || has_video) && financial && urgent {
            "HIGH"
        } else if has_audio || has_video {
            "MEDIUM"
        } else {
            "NONE"
        };
        println!("実際の警告: {level}\n");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn audio_with_financial_urgency_is_high() {
        let mime = "audio/mpeg";
        let body = "至急振込をお願いします";
        let has_audio = mime.starts_with("audio/");
        let financial = body.contains("振込");
        let urgent = body.contains("至急");
        let level = if has_audio && financial && urgent { "HIGH" }
                    else if has_audio { "MEDIUM" } else { "NONE" };
        assert_eq!(level, "HIGH");
    }

    #[test]
    fn video_without_context_is_medium() {
        let mime = "video/mp4";
        let body = "会議の録画です";
        let has_video = mime.starts_with("video/");
        let financial = body.contains("振込");
        let urgent = body.contains("至急");
        let level = if has_video && financial && urgent { "HIGH" }
                    else if has_video { "MEDIUM" } else { "NONE" };
        assert_eq!(level, "MEDIUM");
    }

    #[test]
    fn pdf_is_none() {
        let mime = "application/pdf";
        let has_media = mime.starts_with("audio/") || mime.starts_with("video/");
        let level = if has_media { "MEDIUM" } else { "NONE" };
        assert_eq!(level, "NONE");
    }

    #[test]
    fn english_financial_urgency_detected() {
        let body = "Please wire transfer immediately";
        let financial = ["wire transfer", "payment"].iter().any(|kw| body.contains(kw));
        let urgent = ["urgent", "immediately"].iter().any(|kw| body.contains(kw));
        assert!(financial && urgent);
    }
}
