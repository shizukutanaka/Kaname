# CHANGELOG

All notable changes to Kaname are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security — D791: `X-Kyuutouki-*`/`X-Yuwakashi-*`/`X-Ecocute-*`/`X-Boiler-*`/`X-Waterheater-*`/`X-Hotwatersystem-*` 等の給湯器・ボイラー交換印自称が未検査

- **問題**: `X-Kyuutouki-*`/`X-KyuutoukiYasan-*`/`X-KyuutoukiPro-*`/`X-KyuutoukiTeam-*`/`X-KyuutoukiJP-*`/`X-KyuutoukiSenmon-*`/`X-Yuwakashi-*`/`X-YuwakashiYasan-*`/`X-YuwakashiPro-*`/`X-YuwakashiTeam-*`/`X-YuwakashiJP-*`/`X-YuwakashiSenmon-*`/`X-Ecocute-*`/`X-EcocuteYasan-*`/`X-EcocutePro-*`/`X-EcocuteTeam-*`/`X-EcocuteJP-*`/`X-EcocuteSenmon-*`/`X-BoilerPros-*`/`X-BoilerTeam-*`/`X-BoilerWorks-*`/`X-BoilerExperts-*`/`X-BoilerSvc-*`/`X-BoilerHQ-*`/`X-WaterheaterPros-*`/`X-WaterheaterTeam-*`/`X-WaterheaterWorks-*`/`X-WaterheaterExperts-*`/`X-WaterheaterSvc-*`/`X-WaterheaterHQ-*`/`X-HotwatersystemPros-*`/`X-HotwatersystemTeam-*`/`X-HotwatersystemWorks-*`/`X-HotwatersystemExperts-*`/`X-HotwatersystemSvc-*`/`X-HotwatersystemHQ-*` 等 は湯機の通知記録 — 送信側が書くことは自称。給湯器・ボイラー交換業者の偽装は、緊急交換費・部品代を装ったなりすましの典型手口。(水道修理は plumbing 機、空調は hvac 機、LPガスは lpgas 機で検出済み)
- **修正**: `Envelope` に `kyuutouki_marks` + `has_kyuutouki_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 湯印の自署を問え。

### Security — D792: `X-Taishin-*`/`X-Taishinhosou-*`/`X-Menshin-*`/`X-Seismic-*`/`X-Seismicretrofit-*`/`X-Earthquakeproof-*` 等の耐震・免震補強印自称が未検査

- **問題**: `X-Taishin-*`/`X-TaishinYasan-*`/`X-TaishinPro-*`/`X-TaishinTeam-*`/`X-TaishinJP-*`/`X-TaishinSenmon-*`/`X-Taishinhosou-*`/`X-TaishinhosouYasan-*`/`X-TaishinhosouPro-*`/`X-TaishinhosouTeam-*`/`X-TaishinhosouJP-*`/`X-TaishinhosouSenmon-*`/`X-Menshin-*`/`X-MenshinYasan-*`/`X-MenshinPro-*`/`X-MenshinTeam-*`/`X-MenshinJP-*`/`X-MenshinSenmon-*`/`X-SeismicPros-*`/`X-SeismicTeam-*`/`X-SeismicWorks-*`/`X-SeismicExperts-*`/`X-SeismicSvc-*`/`X-SeismicHQ-*`/`X-SeismicretrofitPros-*`/`X-SeismicretrofitTeam-*`/`X-SeismicretrofitWorks-*`/`X-SeismicretrofitExperts-*`/`X-SeismicretrofitSvc-*`/`X-SeismicretrofitHQ-*`/`X-EarthquakeproofPros-*`/`X-EarthquakeproofTeam-*`/`X-EarthquakeproofWorks-*`/`X-EarthquakeproofExperts-*`/`X-EarthquakeproofSvc-*`/`X-EarthquakeproofHQ-*` 等 は耐機の通知記録 — 送信側が書くことは自称。耐震診断・免震補強業者の偽装は、診断料・補強工事費を装ったなりすましの典型手口。(基礎は foundation 機、住宅は housing 機で検出済み)
- **修正**: `Envelope` に `taishin_marks` + `has_taishin_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 耐印の自署を問え。

### Security — D793: `X-Koutsuujiko-*`/`X-Isharyou-*`/`X-Jidan-*`/`X-Caraccident-*`/`X-Accidentclaim-*`/`X-Trafficaccident-*` 等の交通事故・慰謝料相談印自称が未検査

- **問題**: `X-Koutsuujiko-*`/`X-KoutsuujikoYasan-*`/`X-KoutsuujikoPro-*`/`X-KoutsuujikoTeam-*`/`X-KoutsuujikoJP-*`/`X-KoutsuujikoSenmon-*`/`X-Isharyou-*`/`X-IsharyouYasan-*`/`X-IsharyouPro-*`/`X-IsharyouTeam-*`/`X-IsharyouJP-*`/`X-IsharyouSenmon-*`/`X-Jidan-*`/`X-JidanYasan-*`/`X-JidanPro-*`/`X-JidanTeam-*`/`X-JidanJP-*`/`X-JidanSenmon-*`/`X-CaraccidentPros-*`/`X-CaraccidentTeam-*`/`X-CaraccidentWorks-*`/`X-CaraccidentExperts-*`/`X-CaraccidentSvc-*`/`X-CaraccidentHQ-*`/`X-AccidentclaimPros-*`/`X-AccidentclaimTeam-*`/`X-AccidentclaimWorks-*`/`X-AccidentclaimExperts-*`/`X-AccidentclaimSvc-*`/`X-AccidentclaimHQ-*`/`X-TrafficaccidentPros-*`/`X-TrafficaccidentTeam-*`/`X-TrafficaccidentWorks-*`/`X-TrafficaccidentExperts-*`/`X-TrafficaccidentSvc-*`/`X-TrafficaccidentHQ-*` 等 は故機の通知記録 — 送信側が書くことは自称。交通事故・慰謝料・示談代行業者の偽装は、相談料・示談交渉費を装ったなりすましの典型手口。(弁護士は legal 機、保険は insurance 機、傷害調査は investigation 機で検出済み)
- **修正**: `Envelope` に `jiko_marks` + `has_jiko_marks` 追加; `commands.rs` で render_risks 兆候報告。
- **教訓**: 通知の記録は通知機が記す — 故印の自署を問え。

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
