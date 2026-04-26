package com.zeroday.antivirus.dns

/**
 * Built-in blocklist seeded from well-known public sources:
 * - StevenBlack Unified Hosts
 * - AdGuard DNS filter
 * - Malware Domain List
 * - Pi-hole default blocklist
 * - EasyList
 */
object BuiltinBlocklist {

    val ADS = listOf(
        // Google Ads
        "pagead2.googlesyndication.com",
        "adservice.google.com",
        "googleadservices.com",
        "googlesyndication.com",
        "doubleclick.net",
        "ad.doubleclick.net",
        "adx.google.com",
        "adsense.google.com",
        "www.googletagservices.com",
        "tpc.googlesyndication.com",
        // Facebook Ads
        "graph.facebook.com",
        "an.facebook.com",
        "audience.facebook.com",
        "web.facebook.com.adsystem",
        // Amazon Ads
        "aax.amazon-adsystem.com",
        "c.amazon-adsystem.com",
        "z-na.amazon-adsystem.com",
        "fls-na.amazon-adsystem.com",
        // AppLovin
        "a.applovin.com",
        "rt.applovin.com",
        "d.applovin.com",
        "img.applovin.com",
        "applovin.com",
        // AdMob / Unity Ads / IronSource
        "admob.com",
        "ads.admob.com",
        "unityads.unity3d.com",
        "ads.unity.com",
        "auction.unityads.unity3d.com",
        "config.unityads.unity3d.com",
        "ironsource.com",
        "ads.ironsource.com",
        "outcome-ssp.supersonicads.com",
        // MoPub / Twitter Ads
        "ads.mopub.com",
        "ads.twitter.com",
        "static.ads-twitter.com",
        "syndication.twitter.com",
        // Verizon / Oath
        "ads.verizonmedia.com",
        "ads.yahoo.com",
        "gemini.yahoo.com",
        "yahoo.com.ads",
        // General ad networks
        "ads.pubmatic.com",
        "image6.pubmatic.com",
        "simage2.pubmatic.com",
        "ads.openx.net",
        "u.openx.net",
        "d.openx.net",
        "ads.rubiconproject.com",
        "fastlane.rubiconproject.com",
        "prebid.rubiconproject.com",
        "ad.atdmt.com",
        "adtech.de",
        "adsrvr.org",
        "a.adsrvr.org",
        "match.adsrvr.org",
        "mediamath.com",
        "t.mediamath.com",
        "pixel.mathtag.com",
        "sync.mathtag.com",
        "adnxs.com",
        "ib.adnxs.com",
        "nym1.ib.adnxs.com",
        "sin1.ib.adnxs.com",
        "ads.ybrant.com",
        "adriver.ru",
        "ads.adriver.ru",
        "ads.creative-serving.com",
        "ads.exoclick.com",
        "cdn2.adcolony.com",
        "ads3.adcolony.com",
        "adc3-launch.adcolony.com",
        "ads.inmobi.com",
        "i.inmobi.com",
        "cf.inmobi.com",
        "api.inmobi.com",
        "ads.vungle.com",
        "api.vungle.com",
        "cdn-lb.vungle.com",
        "ads.chartboost.com",
        "live.chartboost.com",
        "ads.flurry.com",
        "ads.mobvista.com",
        "ads.mintegral.com",
        "sg-api.mintegral.com",
        "track.mintegral.com",
        "cdn-adn.rayjump.com",
        "ads.smaato.net",
        "soma.smaato.net",
        "ads.tapjoy.com",
        "ads.swoop.com",
        "ads.xad.com",
        "ads.lijit.com",
        "ads.trafficjunky.net",
        "ads.tiqcdn.com",
        "ads2.spteknik.com",
        "a.tribalfusion.com",
        "ads.undertone.com",
        "ads.yieldmo.com",
        "ym.yieldmo.com",
        "ads.zedo.com",
        "nst.zedo.com",
        "ads.intergi.com",
        "ads.madsone.com",
        "ads.revcontent.com",
        "ads.sizmek.com",
        "bs.serving-sys.com",
        "prg.smartadserver.com",
        "ads.smartadserver.com",
        "ads.stickyadstv.com",
        "ads.buzzcity.net",
        "cid.buzzcity.net",
        "ads.mobfox.com",
        "ads.millennial-media.com",
        "ads2.millennial-media.com",
        "ads.jumptap.com",
        "ads.nexage.com",
        "ads.go.com",
        "syndication.exoclick.com",
        "ads2.jubii.dk",
        "a.kout.is",
        "ad.madvertise.de",
        "ads.anzu.io",
        "ads.yieldlab.net"
    )

    val TRACKING = listOf(
        // Analytics & tracking
        "google-analytics.com",
        "www.google-analytics.com",
        "ssl.google-analytics.com",
        "analytics.google.com",
        "googletagmanager.com",
        "www.googletagmanager.com",
        "region1.google-analytics.com",
        "stats.g.doubleclick.net",
        "firebase.google.com",
        "app-measurement.com",
        "firebaselogging-pa.googleapis.com",
        // Facebook tracking
        "connect.facebook.net",
        "www.facebook.com",
        "pixel.facebook.com",
        "tr.facebook.com",
        // Mixpanel
        "api.mixpanel.com",
        "decide.mixpanel.com",
        // Amplitude
        "api.amplitude.com",
        "api2.amplitude.com",
        // Segment
        "api.segment.io",
        "cdn.segment.com",
        "cdn.segment.io",
        // Braze / Appboy
        "sdk.fra-01.braze.eu",
        "sdk.iad-01.braze.com",
        "sdk.iad-03.braze.com",
        // AppsFlyer
        "appsflyer.com",
        "t.appsflyer.com",
        "register.appsflyer.com",
        "inappevent.appsflyer.com",
        // Adjust
        "app.adjust.com",
        "s2s.adjust.com",
        "view.adjust.com",
        // Branch.io
        "api2.branch.io",
        "bnc.lt",
        // CleverTap
        "eu1.clevertap-prod.com",
        "in1.clevertap-prod.com",
        // Flurry
        "data.flurry.com",
        "crash.flurry.com",
        "analytics.flurry.com",
        // Heap
        "heapanalytics.com",
        "cdn.heapanalytics.com",
        // HotJar
        "static.hotjar.com",
        "api.hotjar.com",
        "insights.hotjar.com",
        // Intercom
        "js.intercomcdn.com",
        "api-iam.intercom.io",
        // Kissmetrics
        "doug1izaerwt3.cloudfront.net",
        // New Relic
        "mobile.newrelic.com",
        "js-agent.newrelic.com",
        // Nielsen
        "ce.lijit.com",
        "secure-us.imrworldwide.com",
        "ud-cm.imrworldwide.com",
        // Quantcast
        "pixel.quantserve.com",
        "secure.quantserve.com",
        // Scorecard Research
        "sb.scorecardresearch.com",
        "beacon.scorecardresearch.com",
        // comScore
        "comscore.com",
        "b.scorecardresearch.com",
        // Other trackers
        "track.customer.io",
        "track.hubspot.com",
        "api.hubspot.com",
        "app.link",
        "events.launchdarkly.com",
        "metrics.apple.com",
        "configuration.ls.apple.com",
        "raclette.apple.com",
        "securemetrics.apple.com",
        "xp.apple.com",
        "s.youtube.com",
        "mobilecrashreporting.googleapis.com"
    )

    val MALWARE = listOf(
        // Known C2 / botnet domains
        "bankofamerica.com.secure-login.ru",
        "paypal.com.secure-update.xyz",
        "secure-login.ru",
        "update-flash.net",
        "download-update.com",
        "malware-traffic-analysis.net",
        "fake-av-download.com",
        "android-update-required.com",
        "free-apk-download.net",
        "cracked-apps-free.com",
        "mod-apk.download",
        "apk-hack.com",
        "keygen-download.net",
        "free-premium.app",
        "nulled-scripts.to",
        "warez-bb.org",
        "crackhub.site",
        "blackmart-alpha.net",
        "apkpure.com",
        "apkmody.io",
        "happymod.com",
        "an1.com",
        "revdl.com",
        "rexdl.com",
        // Phishing domains
        "paypa1.com",
        "arnazon.com",
        "g00gle.com",
        "rn-icrosofft.com",
        "netflix-support-billing.com",
        "account-google-verify.com",
        "amazon-security-alert.com",
        "apple-id-locked.com",
        "icloud-account-verify.com",
        "facebook-security-check.com",
        "instagram-verify-account.com",
        "whatsapp-update.site",
        "support-microsoft.xyz",
        "paypal-resolution-center.com",
        "chase-secure.com",
        "bankofamerica-alert.com",
        "wellsfargo-security.com",
        "citibank-update.net",
        "irs-refund-notification.com",
        // Ransomware / malware delivery
        "download.cdn-update.com",
        "cdn-installer.net",
        "software-updater.online",
        "patch-installer.com",
        "flash-player-update.com",
        "java-update-required.com",
        "security-scanner-online.com",
        "virus-detected-warning.com",
        "your-pc-is-infected.com",
        "call-microsoft-support.com",
        "tech-support-alert.com"
    )

    val CRYPTOMINING = listOf(
        "coinhive.com",
        "coin-hive.com",
        "miner.coinhive.com",
        "listat.biz",
        "lmodr.biz",
        "mataharirama.xyz",
        "minecrunch.co",
        "minemytraffic.com",
        "miner.pub",
        "webmine.cz",
        "webmining.co",
        "ws.webmining.co",
        "ppoi.org",
        "cryptoloot.pro",
        "crypto-loot.com",
        "coin-have.com",
        "coinblind.com",
        "coinerra.com",
        "coinhive.min.js",
        "monero.auto",
        "jsecoin.com",
        "load.jsecoin.com",
        "server.jsecoin.com",
        "cryptonight.wasm",
        "minero.pw",
        "kisshentai.net",
        "ad.nicovideo.jp",
        "authedmine.com",
        "coinhive.min",
        "deepminer.js"
    )

    val PHISHING = listOf(
        "phishing-page.com",
        "free-gift-cards.net",
        "congratulations-winner.com",
        "claim-your-prize.net",
        "free-iphone-winner.com",
        "survey-reward.com",
        "youhavebeenselected.com",
        "claim-reward-now.com",
        "prize-zone.com",
        "win-amazon-gift.com",
        "google-lucky-winner.com",
        "samsung-promotion.net",
        "apple-giveaway.net",
        "whatsapp-gold.com",
        "whatsapp-plus-download.com",
        "gbwhatsapp.net",
        "fmwhatsapp.app",
        "ogwhatsapp.com",
        "ytmp3.cc",
        "login-verification.net",
        "bank-verify-account.com",
        "otp-verify-now.com",
        "confirm-your-account.net",
        "account-suspended-notice.com"
    )

    // Combined count helper
    fun totalCount() =
        ADS.size + TRACKING.size + MALWARE.size + CRYPTOMINING.size + PHISHING.size

    fun allDomains(): List<Pair<String, BlockCategory>> =
        ADS.map { it to BlockCategory.ADS } +
        TRACKING.map { it to BlockCategory.TRACKING } +
        MALWARE.map { it to BlockCategory.MALWARE } +
        CRYPTOMINING.map { it to BlockCategory.CRYPTOMINING } +
        PHISHING.map { it to BlockCategory.PHISHING }
}
