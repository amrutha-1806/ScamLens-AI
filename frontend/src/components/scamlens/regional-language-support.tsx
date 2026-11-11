import * as React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Globe,
  HelpCircle,
  Info,
  Languages,
  PhoneCall,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { AnalysisResult, RiskLevel, SupportedLanguage } from "@/lib/scamlens-types";
import { Badge, Button, Card, cn } from "./ui";

export interface LanguageOption {
  code: SupportedLanguage;
  label: string;
  nativeLabel: string;
  scriptBadge: string;
  placeholder: string;
  sampleScams: Array<{
    title: string;
    category: string;
    text: string;
  }>;
}

export const SUPPORTED_LANGUAGES: LanguageOption[] = [
  {
    code: "en",
    label: "English",
    nativeLabel: "English",
    scriptBadge: "Latin (Primary ML)",
    placeholder: "Paste an SMS, WhatsApp, email, or payment message in English...",
    sampleScams: [
      {
        title: "Bank KYC Suspension & OTP Demand",
        category: "Banking Phishing",
        text: "URGENT: Your SBI Bank account will be blocked today due to incomplete KYC. Act immediately to verify your account at http://sbi-kyc-update-online.xyz or share your OTP with our officer.",
      },
      {
        title: "Lottery / Reward Claim Lure",
        category: "Prize Scam",
        text: "Congratulations! You have won Rs 25,000 cashback reward. Claim your reward now! Urgent payment required of Rs 499 processing fee to release your prize.",
      },
    ],
  },
  {
    code: "hi",
    label: "Hindi",
    nativeLabel: "हिन्दी (Hindi)",
    scriptBadge: "Devanagari + Hybrid Rules",
    placeholder: "यहाँ संदिग्ध एसएमएस, व्हाट्सएप या बैंक संदेश पेस्ट करें...",
    sampleScams: [
      {
        title: "बैंक खाता बंद और केवाईसी (KYC) चेतावनी",
        category: "Banking Alert (Hindi)",
        text: "तुरंत ध्यान दें: आपका खाता बंद हो जाएगा क्योंकि आपका केवाईसी अपडेट अधूरा है। अपना ओटीपी साझा करें या अभी सत्यापित करें: http://kyc-verify-bank-india.top/login",
      },
      {
        title: "बिजली बिल कनेक्शन कटने की धमकी",
        category: "Utility Scam (Hindi)",
        text: "अंतिम चेतावनी: आज रात 9:30 बजे आपका बिजली कनेक्शन काट दिया जाएगा क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। तुरंत भुगतान करें या अधिकारी से संपर्क करें।",
      },
    ],
  },
  {
    code: "hinglish",
    label: "Hinglish",
    nativeLabel: "Hinglish (Hindi-English)",
    scriptBadge: "Romanized Hindi + ML",
    placeholder: "Paste a Hinglish SMS or WhatsApp message (e.g., 'Aapka account band ho jayega')...",
    sampleScams: [
      {
        title: "Account Band & OTP Share Scam",
        category: "Hinglish Phishing",
        text: "URGENT: Aapka bank khata aaj band ho jayega kyonki pan card link nahi hai. Turant verify karein http://hdfc-pan-verify.xyz par ya apna OTP share karein.",
      },
      {
        title: "Bijli Bill Disconnection Threat",
        category: "Hinglish Utility Scam",
        text: "Dear consumer, aapka bijli connection aaj raat 9 baje kat jayega. Immediately call electricity helpline 9876500000 and urgent payment required to avoid disconnection.",
      },
    ],
  },
  {
    code: "kn",
    label: "Kannada",
    nativeLabel: "ಕನ್ನಡ (Kannada)",
    scriptBadge: "Kannada Script + Hybrid Rules",
    placeholder: "ಸಂಶಯಾಸ್ಪದ ಸಂದೇಶವನ್ನು ಇಲ್ಲಿ ಪೇಸ್ಟ್ ಮಾಡಿ (ಕನ್ನಡ ಅಥವಾ ಇಂಗ್ಲಿಷ್)...",
    sampleScams: [
      {
        title: "ಬ್ಯಾಂಕ್ ಖಾತೆ ಬ್ಲಾಕ್ ಮತ್ತು ಕೆವೈಸಿ (KYC) ಎಚ್ಚರಿಕೆ",
        category: "Banking Alert (Kannada)",
        text: "ತುರ್ತು ಸೂಚನೆ: ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗಿದೆ. ತಕ್ಷಣ ಕೆವೈಸಿ ಅಪ್ಡೇಟ್ ಮಾಡಿ ಅಥವಾ ನಿಮ್ಮ ಒಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ: http://karnataka-bank-kyc-update.xyz",
      },
      {
        title: "ಬಹುಮಾನ ಮತ್ತು ಲಾಟರಿ ಆಮಿಷ (Prize Lure)",
        category: "Prize Scam (Kannada)",
        text: "ಅಭಿನಂದನೆಗಳು! ನಿಮಗೆ ರೂ 50,000 ಬಹುಮಾನ ಗೆದ್ದಿದ್ದೀರಿ. ನಿಮ್ಮ ಬಹುಮಾನ ಪಡೆಯಲು ತಕ್ಷಣ ಶುಲ್ಕ ಪಾವತಿಸಿ ಮತ್ತು ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಪರಿಶೀಲಿಸಿ.",
      },
    ],
  },
];

interface LocalizedUiCopy {
  languageDisclosureTitle: string;
  languageDisclosureBody: string;
  verdictLabel: Record<"Scam/Phishing" | "Legitimate", string>;
  riskLevelLabel: Record<RiskLevel, string>;
  nextStepsTitle: string;
  nextStepsSubtitle: string;
  highRiskActions: string[];
  lowRiskActions: string[];
  reportingTitle: string;
  reportingSubtitle: string;
  officialPortalBadge: string;
  generalAdviceBadge: string;
  noAutoReportDisclaimer: string;
  indicatorHeading: string;
}

export const LOCALIZED_UI_COPY: Record<SupportedLanguage, LocalizedUiCopy> = {
  en: {
    languageDisclosureTitle: "English ML Model + Multilingual Rule Assistance",
    languageDisclosureBody:
      "The core Random Forest classifier was trained on 5,574 English SMS messages (UCI SMS Spam Collection). English tokens are scored directly by the ML model; Hindi, Hinglish, and Kannada phrases are evaluated via deterministic rule-based pattern matching and translated interface guidance.",
    verdictLabel: {
      "Scam/Phishing": "Scam / Phishing Detected",
      Legitimate: "No Primary Scam Pattern Detected",
    },
    riskLevelLabel: {
      Low: "Low Risk",
      Suspicious: "Suspicious",
      High: "High Risk",
      "Very High": "Very High Risk",
    },
    nextStepsTitle: "What should I do next?",
    nextStepsSubtitle: "Practical protective steps tailored to this risk level and official cybercrime reporting channels.",
    highRiskActions: [
      "Do not click any links, shorten URLs, or download attachments from this message.",
      "Do not share OTPs, UPI PINs, CVV numbers, or net-banking passwords with anyone.",
      "Do not send money, scan unknown QR codes, or approve UPI collect requests.",
      "Contact your bank or service provider only through the official number on the back of your card or official website.",
      "Block and report the sender on your messaging app or telecom carrier.",
      "Keep unedited screenshots of the message, sender number, and transaction IDs as evidence.",
    ],
    lowRiskActions: [
      "Even when no high-risk indicators are triggered, never share OTPs, PINs, or passwords if requested later.",
      "Verify unexpected payment or account requests independently via the organization's official app or website.",
      "Double-check the exact domain spelling before signing in or entering personal details.",
    ],
    reportingTitle: "Official Cybercrime Reporting Portals",
    reportingSubtitle: "Select your country or region to view verified government reporting channels.",
    officialPortalBadge: "Official Government Portal",
    generalAdviceBadge: "General Protective Guidance",
    noAutoReportDisclaimer:
      "Important: SCAMLENS AI is an educational & analytical tool. It never automatically files a police or cybercrime complaint on your behalf — use the official portal or helpline below to submit a formal report.",
    indicatorHeading: "Translated Summary & Explanation",
  },
  hi: {
    languageDisclosureTitle: "पारदर्शी भाषा सूचना (ML मॉडल और हिंदी नियम सहायता)",
    languageDisclosureBody:
      "मुख्य Random Forest ML मॉडल अंग्रेजी एसएमएस डेटासेट (UCI SMS) पर प्रशिक्षित है। हिंदी (देवनागरी) और हिंग्लिश संदेशों में संदिग्ध वाक्यांशों की पहचान नियम-आधारित (Rule-Based) पैटर्न और अनुवादित सुरक्षा मार्गदर्शन द्वारा की जाती है। इसे बहुभाषी ML सटीकता का दावा नहीं माना जाना चाहिए।",
    verdictLabel: {
      "Scam/Phishing": "धोखाधड़ी / फ़िशिंग (Scam/Phishing) की आशंका",
      Legitimate: "कम जोखिम / सामान्य संदेश (Legitimate)",
    },
    riskLevelLabel: {
      Low: "कम जोखिम (Low)",
      Suspicious: "संदिग्ध (Suspicious)",
      High: "उच्च जोखिम (High)",
      "Very High": "अत्यधिक जोखिम (Very High)",
    },
    nextStepsTitle: "अब मुझे आगे क्या करना चाहिए? (What should I do next?)",
    nextStepsSubtitle: "इस जोखिम स्तर के अनुसार व्यावहारिक सुरक्षा कदम और आधिकारिक साइबर अपराध रिपोर्टिंग पोर्टल।",
    highRiskActions: [
      "अज्ञात लिंक पर क्लिक न करें और किसी भी अनजान फाइल को डाउनलोड न करें।",
      "अपना ओटीपी (OTP), यूपीआई पिन (UPI PIN), पासवर्ड या सीवीवी किसी के साथ साझा न करें।",
      "पैसे न भेजें और न ही किसी अनजान QR कोड को स्कैन करें (पैसे प्राप्त करने के लिए पिन की आवश्यकता नहीं होती)।",
      "केवल आधिकारिक वेबसाइट या बैंक कार्ड के पीछे दिए गए नंबर के माध्यम से ही संस्था से संपर्क करें।",
      "संदेश भेजने वाले नंबर को तुरंत ब्लॉक करें और स्पैम के रूप में रिपोर्ट करें।",
      "सबूत के तौर पर संदेश, फोन नंबर और लेनदेन का स्क्रीनशॉट सुरक्षित रखें।",
    ],
    lowRiskActions: [
      "कम जोखिम दिखने पर भी कभी भी फोन या चैट पर अपना OTP या UPI पिन साझा न करें।",
      "किसी भी भुगतान या खाता अपडेट के अनुरोध की पुष्टि हमेशा आधिकारिक ऐप से करें।",
      "लॉगिन करने से पहले वेबसाइट के डोमेन नाम की स्पेलिंग अवश्य जांचें।",
    ],
    reportingTitle: "आधिकारिक साइबर अपराध रिपोर्टिंग (Official Reporting)",
    reportingSubtitle: "आधिकारिक सरकारी पोर्टल और हेल्पलाइन देखने के लिए अपना देश चुनें।",
    officialPortalBadge: "आधिकारिक सरकारी पोर्टल",
    generalAdviceBadge: "सामान्य सुरक्षा सलाह",
    noAutoReportDisclaimer:
      "महत्वपूर्ण: SCAMLENS AI आपकी ओर से स्वतः कोई शिकायत दर्ज नहीं करता है। आधिकारिक शिकायत दर्ज करने के लिए नीचे दिए गए सरकारी पोर्टल या हेल्पलाइन 1930 का उपयोग करें।",
    indicatorHeading: "हिंदी सुरक्षा सारांश (Translated Explanation)",
  },
  hinglish: {
    languageDisclosureTitle: "Language Transparency: English ML + Hinglish Pattern Rules",
    languageDisclosureBody:
      "Core Random Forest ML model English SMS dataset par trained hai. Hinglish words (jaise 'khata band', 'turant verify', 'OTP share karein') ko SCAMLENS ke hybrid rule-based engine aur English ML tokens ke combination se analyze kiya gaya hai.",
    verdictLabel: {
      "Scam/Phishing": "Scam / Phishing Alert (Dhokhadhadi ka Khatra)",
      Legitimate: "Low Risk / Normal Message",
    },
    riskLevelLabel: {
      Low: "Low Risk (Kam Khatra)",
      Suspicious: "Suspicious (Shakiya Message)",
      High: "High Risk (Zyada Khatra)",
      "Very High": "Very High Risk (Bahut Zyada Khatra)",
    },
    nextStepsTitle: "Ab mujhe aage kya karna chahiye? (What should I do next?)",
    nextStepsSubtitle: "Is message ke risk level ke hisaab se zaroori safety steps aur official reporting links.",
    highRiskActions: [
      "Kisi bhi unknown link par click mat karein aur koi अनजान APK/file download na karein.",
      "Apna OTP, UPI PIN, ATM PIN ya net-banking password kisi ke saath share mat karein.",
      "Paise mat bhejein aur cashback/refund paane ke liye koi QR code scan na karein.",
      "Bank ya company se sirf unke official helpline number ya official app ke zariye hi baat karein.",
      "Sender ko turant block aur report karein.",
      "Evidence ke liye message aur sender details ka screenshot save karke rakhein.",
    ],
    lowRiskActions: [
      "Agar message normal lage tab bhi kabhi OTP, PIN ya password share na karein.",
      "Payment ya KYC request ko hamesha official app me jakar cross-check karein.",
      "Website link ki spelling dhyan se check karein.",
    ],
    reportingTitle: "Official Cybercrime Reporting Portals",
    reportingSubtitle: "Official government cyber helpline dekhne ke liye apna country select karein.",
    officialPortalBadge: "Official Government Portal",
    generalAdviceBadge: "General Safety Advice",
    noAutoReportDisclaimer:
      "Note: SCAMLENS AI automatically koi police complaint file nahi karta hai. Official complaint darj karne ke liye neeche diye gaye government portal ya 1930 helpline par sampark karein.",
    indicatorHeading: "Hinglish Summary & Guidance",
  },
  kn: {
    languageDisclosureTitle: "ಭಾಷಾ ಪಾರದರ್ಶಕತೆ ಮಾಹಿತಿ (ML ಮಾಡೆಲ್ ಮತ್ತು ಕನ್ನಡ ನಿಯಮ ಬೆಂಬಲ)",
    languageDisclosureBody:
      "ಮುಖ್ಯ Random Forest ML ಮಾಡೆಲ್ ಅನ್ನು ಇಂಗ್ಲಿಷ್ SMS ಡೇಟಾಸೆಟ್‌ನಲ್ಲಿ ತರಬೇತಿ ಮಾಡಲಾಗಿದೆ. ಕನ್ನಡ (Kannada) ಮತ್ತು ಕಂಗ್ಲಿಷ್ ಸಂದೇಶಗಳಲ್ಲಿನ ಸಂಶಯಾಸ್ಪದ ಪದಗಳನ್ನು ನಿಯಮ-ಆಧಾರಿತ (Rule-Based) ಪ್ಯಾಟರ್ನ್‌ಗಳು ಮತ್ತು ಅನುವಾದಿತ ಸುರಕ್ಷತಾ ಮಾರ್ಗದರ್ಶನದ ಮೂಲಕ ವಿಶ್ಲೇಷಿಸಲಾಗುತ್ತದೆ.",
    verdictLabel: {
      "Scam/Phishing": "ವಂಚನೆ / ಫಿಶಿಂಗ್ ಪತ್ತೆಯಾಗಿದೆ (Scam/Phishing)",
      Legitimate: "ಕಡಿಮೆ ಅಪಾಯ / ಸಾಮಾನ್ಯ ಸಂದೇಶ (Legitimate)",
    },
    riskLevelLabel: {
      Low: "ಕಡಿಮೆ ಅಪಾಯ (Low)",
      Suspicious: "ಸಂಶಯಾಸ್ಪದ (Suspicious)",
      High: "ಹೆಚ್ಚಿನ ಅಪಾಯ (High)",
      "Very High": "ಅತಿ ಹೆಚ್ಚಿನ ಅಪಾಯ (Very High)",
    },
    nextStepsTitle: "ನಾನು ಮುಂದೆ ಏನು ಮಾಡಬೇಕು? (What should I do next?)",
    nextStepsSubtitle: "ಈ ಅಪಾಯದ ಮಟ್ಟಕ್ಕೆ ಅನುಗುಣವಾಗಿ ನೀವು ತೆಗೆದುಕೊಳ್ಳಬೇಕಾದ ಸುರಕ್ಷತಾ ಕ್ರಮಗಳು ಮತ್ತು ಅಧಿಕೃತ ದೂರು ಪೋರ್ಟಲ್‌ಗಳು.",
    highRiskActions: [
      "ಅಪರಿಚಿತ ಲಿಂಕ್‌ಗಳನ್ನು ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಯಾವುದೇ ಅನಧಿಕೃತ ಆಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಬೇಡಿ.",
      "ನಿಮ್ಮ ಒಟಿಪಿ (OTP), ಯುಪಿಐ ಪಿನ್ (UPI PIN), ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಅನ್ನು ಯಾರೊಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
      "ಹಣ ಕಳುಹಿಸಬೇಡಿ ಅಥವಾ ಹಣ ಪಡೆಯಲು QR ಕೋಡ್ ಸ್ಕ್ಯಾನ್ ಮಾಡಬೇಡಿ (ಹಣ ಸ್ವೀಕರಿಸಲು ಪಿನ್ ಅಗತ್ಯವಿಲ್ಲ).",
      "ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ಕಾರ್ಡ್‌ನಲ್ಲಿರುವ ಅಧಿಕೃತ ಸಂಖ್ಯೆಯ ಮೂಲಕ ಮಾತ್ರ ಸಂಸ್ಥೆಯನ್ನು ಸಂಪರ್ಕಿಸಿ.",
      "ಸಂದೇಶ ಕಳುಹಿಸಿದವರನ್ನು ತಕ್ಷಣ ಬ್ಲಾಕ್ ಮಾಡಿ ಮತ್ತು ವರದಿ (Report) ಮಾಡಿ.",
      "ಸಾಕ್ಷಿಗಾಗಿ ಸಂದೇಶ ಮತ್ತು ಫೋನ್ ಸಂಖ್ಯೆಯ ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ಗಳನ್ನು ಉಳಿಸಿಕೊಳ್ಳಿ.",
    ],
    lowRiskActions: [
      "ಯಾವುದೇ ಎಚ್ಚರಿಕೆ ಕಂಡುಬರದಿದ್ದರೂ ಸಹ, ನಿಮ್ಮ OTP ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಅನ್ನು ಯಾರಿಗೂ ನೀಡಬೇಡಿ.",
      "ಖಾತೆ ಅಥವಾ ಪಾವತಿ ವಿನಂತಿಗಳನ್ನು ಅಧಿಕೃತ ಆಪ್ ಮೂಲಕವೇ ಪರಿಶೀಲಿಸಿ.",
      "ಯಾವುದೇ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ವಿವರ ನಮೂದಿಸುವ ಮೊದಲು ವಿಳಾಸವನ್ನು (URL) ಪರಿಶೀಲಿಸಿ.",
    ],
    reportingTitle: "ಅಧಿಕೃತ ಸೈಬರ್ ಕ್ರೈಮ್ ವರದಿ ಪೋರ್ಟಲ್‌ಗಳು (Official Reporting)",
    reportingSubtitle: "ಅಧಿಕೃತ ಸರ್ಕಾರಿ ವರದಿ ಪೋರ್ಟಲ್ ನೋಡಲು ನಿಮ್ಮ ದೇಶವನ್ನು ಆಯ್ಕೆಮಾಡಿ.",
    officialPortalBadge: "ಅಧಿಕೃತ ಸರ್ಕಾರಿ ಪೋರ್ಟಲ್",
    generalAdviceBadge: "ಸಾಮಾನ್ಯ ಸುರಕ್ಷತಾ ಸಲಹೆ",
    noAutoReportDisclaimer:
      "ಗಮನಿಸಿ: SCAMLENS AI ನಿಮ್ಮ ಪರವಾಗಿ ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಯಾವುದೇ ದೂರನ್ನು ದಾಖಲಿಸುವುದಿಲ್ಲ. ಅಧಿಕೃತ ದೂರು ನೀಡಲು ಕೆಳಗಿನ ಸರ್ಕಾರಿ ಪೋರ್ಟಲ್ ಅಥವಾ ಸಹಾಯವಾಣಿ 1930 ಅನ್ನು ಬಳಸಿ.",
    indicatorHeading: "ಕನ್ನಡ ಸುರಕ್ಷತಾ ಸಾರಾಂಶ (Translated Guidance)",
  },
};

export interface CountryReportingChannel {
  code: string;
  name: string;
  agencyName: string;
  portalName: string;
  portalUrl: string;
  helpline: string;
  emergencyNote: string;
}

export const COUNTRY_REPORTING_CHANNELS: CountryReportingChannel[] = [
  {
    code: "IN",
    name: "India",
    agencyName: "Ministry of Home Affairs (I4C)",
    portalName: "National Cyber Crime Reporting Portal",
    portalUrl: "https://cybercrime.gov.in/",
    helpline: "1930",
    emergencyNote: "Dial 1930 immediately for financial cyber fraud (UPI, banking, OTP scams) or file a complaint at cybercrime.gov.in.",
  },
  {
    code: "US",
    name: "United States",
    agencyName: "FBI / Federal Trade Commission",
    portalName: "Internet Crime Complaint Center (IC3) & ReportFraud.ftc.gov",
    portalUrl: "https://www.ic3.gov/",
    helpline: "1-877-382-4357 (FTC)",
    emergencyNote: "Forward phishing texts to 7726 (SPAM) and report financial cybercrime to ic3.gov or reportfraud.ftc.gov.",
  },
  {
    code: "UK",
    name: "United Kingdom",
    agencyName: "National Cyber Security Centre (NCSC)",
    portalName: "Action Fraud — National Fraud & Cyber Crime Reporting Centre",
    portalUrl: "https://www.actionfraud.police.uk/",
    helpline: "0300 123 2040 / 159 (Bank Hotline)",
    emergencyNote: "Call 159 to reach your bank safely if you suspect fraud, forward scam SMS to 7726, and report at actionfraud.police.uk.",
  },
  {
    code: "AU",
    name: "Australia",
    agencyName: "National Anti-Scam Centre (ACCC) / ASD",
    portalName: "Scamwatch & ReportCyber (cyber.gov.au)",
    portalUrl: "https://www.scamwatch.gov.au/",
    helpline: "1300 292 371 (ACSC)",
    emergencyNote: "Contact your bank immediately if money or credentials were shared, and submit a report at scamwatch.gov.au.",
  },
  {
    code: "CA",
    name: "Canada",
    agencyName: "RCMP / Canadian Anti-Fraud Centre",
    portalName: "Canadian Anti-Fraud Centre (CAFC)",
    portalUrl: "https://antifraudcentre-centreantifraude.ca/",
    helpline: "1-888-495-8501",
    emergencyNote: "Forward spam texts to 7726 and report phishing or financial fraud to the Canadian Anti-Fraud Centre.",
  },
  {
    code: "SG",
    name: "Singapore",
    agencyName: "Singapore Police Force",
    portalName: "ScamShield & SPF Anti-Scam Centre",
    portalUrl: "https://www.scamshield.gov.sg/",
    helpline: "1799 (ScamShield Helpline)",
    emergencyNote: "Call the 24/7 ScamShield Helpline at 1799 to verify or report suspected scams in Singapore.",
  },
  {
    code: "INTL",
    name: "Other / International",
    agencyName: "Local National CERT / Financial Regulator",
    portalName: "Contact Your Bank & National Computer Emergency Response Team",
    portalUrl: "https://www.first.org/members/teams/",
    helpline: "Contact Official Number on Back of Your Bank Card",
    emergencyNote: "If your country is not listed above, contact your bank's official fraud desk immediately and report to your national police cybercrime unit.",
  },
];

export function translateIndicatorToLanguage(indicator: string, lang: SupportedLanguage): string {
  if (lang === "en") return indicator;
  const lower = indicator.toLowerCase();

  if (lang === "hi") {
    if (lower.includes("otp") || lower.includes("pin") || lower.includes("password") || lower.includes("credential")) {
      return `${indicator} — (हिंदी व्याख्या: यह संदेश गोपनीय ओटीपी, पिन या खाता पासवर्ड मांगने का प्रयास कर रहा है।)`;
    }
    if (lower.includes("urgent") || lower.includes("immediately") || lower.includes("blocked") || lower.includes("suspended") || lower.includes("तुरंत") || lower.includes("खाता बंद")) {
      return `${indicator} — (हिंदी व्याख्या: आपको डराकर तुरंत कदम उठाने के लिए कृत्रिम दबाव या खाता बंद होने की धमकी दी जा रही है।)`;
    }
    if (lower.includes("reward") || lower.includes("prize") || lower.includes("lottery") || lower.includes("won") || lower.includes("इनाम")) {
      return `${indicator} — (हिंदी व्याख्या: मुफ्त इनाम, लॉटरी या कैशबैक का लालच देकर फंसाने की कोशिश की गई है।)`;
    }
    if (lower.includes("url") || lower.includes("link") || lower.includes("http") || lower.includes("domain")) {
      return `${indicator} — (हिंदी व्याख्या: संदेश में संदिग्ध वेब लिंक या असुरक्षित डोमेन शामिल है।)`;
    }
    return `${indicator} — (हिंदी व्याख्या: संदेश में संदिग्ध भाषा या धोखाधड़ी के संकेत मिले हैं।)`;
  }

  if (lang === "hinglish") {
    if (lower.includes("otp") || lower.includes("pin") || lower.includes("password") || lower.includes("credential")) {
      return `${indicator} — (Hinglish: Yeh message aapka secret OTP, PIN ya account password maang raha hai.)`;
    }
    if (lower.includes("urgent") || lower.includes("immediately") || lower.includes("blocked") || lower.includes("band")) {
      return `${indicator} — (Hinglish: Account block hone ka darr dikhakar turant action lene ka pressure banaya ja raha hai.)`;
    }
    if (lower.includes("reward") || lower.includes("prize") || lower.includes("lottery") || lower.includes("won")) {
      return `${indicator} — (Hinglish: Fake prize, lottery ya cashback reward ka lalach diya ja raha hai.)`;
    }
    if (lower.includes("url") || lower.includes("link") || lower.includes("http") || lower.includes("domain")) {
      return `${indicator} — (Hinglish: Message me ek suspicious link ya unverified domain paya gaya hai.)`;
    }
    return `${indicator} — (Hinglish: Is message me scam ya phishing ke lakshan mile hain.)`;
  }

  if (lang === "kn") {
    if (lower.includes("otp") || lower.includes("pin") || lower.includes("password") || lower.includes("credential") || lower.includes("ಒಟಿಪಿ")) {
      return `${indicator} — (ಕನ್ನಡ ವಿವರಣೆ: ಈ ಸಂದೇಶವು ನಿಮ್ಮ ರಹಸ್ಯ OTP, ಪಿನ್ ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಕೇಳಲು ಪ್ರಯತ್ನಿಸುತ್ತಿದೆ.)`;
    }
    if (lower.includes("urgent") || lower.includes("immediately") || lower.includes("blocked") || lower.includes("ತಕ್ಷಣ") || lower.includes("ಬ್ಲಾಕ್")) {
      return `${indicator} — (ಕನ್ನಡ ವಿವರಣೆ: ಖಾತೆ ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ ಎಂದು ಭಯಪಡಿಸಿ ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳುವಂತೆ ಒತ್ತಡ ಹೇರಲಾಗುತ್ತಿದೆ.)`;
    }
    if (lower.includes("reward") || lower.includes("prize") || lower.includes("lottery") || lower.includes("ಬಹುಮಾನ")) {
      return `${indicator} — (ಕನ್ನಡ ವಿವರಣೆ: ನಕಲಿ ಬಹುಮಾನ ಅಥವಾ ಲಾಟರಿ ಆಮಿಷ ತೋರಿಸಿ ವಂಚಿಸುವ ಪ್ರಯತ್ನವಾಗಿದೆ.)`;
    }
    if (lower.includes("url") || lower.includes("link") || lower.includes("http") || lower.includes("domain")) {
      return `${indicator} — (ಕನ್ನಡ ವಿವರಣೆ: ಸಂದೇಶದಲ್ಲಿ ಸಂಶಯಾಸ್ಪದ ವೆಬ್ ಲಿಂಕ್ ಕಂಡುಬಂದಿದೆ.)`;
    }
    return `${indicator} — (ಕನ್ನಡ ವಿವರಣೆ: ಈ ಸಂದೇಶದಲ್ಲಿ ಸಂಶಯಾಸ್ಪದ ವಂಚನೆಯ ಸೂಚನೆಗಳು ಕಂಡುಬಂದಿವೆ.)`;
  }

  return indicator;
}

export function LanguageSelectorBar({
  selectedLanguage,
  onSelectLanguage,
  onLoadSample,
}: {
  selectedLanguage: SupportedLanguage;
  onSelectLanguage: (lang: SupportedLanguage) => void;
  onLoadSample?: (text: string, lang: SupportedLanguage) => void;
}) {
  const activeOption =
    SUPPORTED_LANGUAGES.find((l) => l.code === selectedLanguage) ?? SUPPORTED_LANGUAGES[0]!;
  const copy = LOCALIZED_UI_COPY[selectedLanguage];

  return (
    <div
      className="rounded-xl border border-slate-800/90 bg-slate-950/65 p-3.5 space-y-3"
      data-testid="regional-language-selector"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
            <Languages className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Regional Language Support
              </span>
              <Badge tone="info">{activeOption.scriptBadge}</Badge>
            </div>
            <p className="text-[11px] text-slate-400">
              Analyze messages and view explanations & safety guidance in English, Hindi, Hinglish, or Kannada
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Select Analysis Language">
          {SUPPORTED_LANGUAGES.map((lang) => {
            const active = lang.code === selectedLanguage;
            return (
              <button
                key={lang.code}
                type="button"
                data-testid={`lang-btn-${lang.code}`}
                onClick={() => onSelectLanguage(lang.code)}
                className={cn(
                  "rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-all",
                  active
                    ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-200 shadow-sm shadow-cyan-950/50"
                    : "border-slate-800 bg-slate-900/70 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                )}
              >
                {lang.nativeLabel}
              </button>
            );
          })}
        </div>
      </div>

      {/* Honest Scope Disclosure */}
      <div className="flex items-start gap-2 rounded-lg border border-slate-800/80 bg-slate-900/50 px-3 py-2 text-[11px] text-slate-400 leading-relaxed">
        <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">{copy.languageDisclosureTitle}: </span>
          {copy.languageDisclosureBody}
        </div>
      </div>

      {/* Quick Regional Sample Buttons */}
      {onLoadSample && (
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 mr-1">
            Load {activeOption.label} Sample:
          </span>
          {activeOption.sampleScams.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              data-testid={`regional-sample-${activeOption.code}-${idx}`}
              onClick={() => onLoadSample(sample.text, activeOption.code)}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900/80 px-2.5 py-1 text-[11px] text-slate-300 hover:border-cyan-500/40 hover:bg-cyan-500/10 hover:text-cyan-200 transition"
            >
              <Sparkles className="h-3 w-3 text-cyan-400" />
              <span>{sample.title}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Feature 4 — Safety Guidance and Official Reporting ("What should I do next?")
 * Also supports regional language translation from Feature 6.
 */
export function SafetyGuidanceAndReportingCard({
  result,
  selectedLanguage = "en",
}: {
  result: AnalysisResult;
  selectedLanguage?: SupportedLanguage | undefined;
}) {
  const [selectedCountryCode, setSelectedCountryCode] = React.useState<string>("IN");
  const copy = LOCALIZED_UI_COPY[selectedLanguage];

  const isElevatedRisk =
    result.prediction === "Scam/Phishing" ||
    result.riskLevel === "Suspicious" ||
    result.riskLevel === "High" ||
    result.riskLevel === "Very High";

  const actions = isElevatedRisk ? copy.highRiskActions : copy.lowRiskActions;
  const activeCountry =
    COUNTRY_REPORTING_CHANNELS.find((c) => c.code === selectedCountryCode) ??
    COUNTRY_REPORTING_CHANNELS[0]!;

  return (
    <Card
      className={cn(
        "p-5 space-y-5 border",
        isElevatedRisk
          ? "border-amber-500/30 bg-gradient-to-br from-slate-900/95 via-slate-900/90 to-amber-950/15"
          : "border-emerald-500/25 bg-slate-900/80"
      )}
      data-testid="safety-guidance-reporting-card"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-start gap-3">
          <div
            className={cn(
              "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border",
              isElevatedRisk
                ? "border-amber-500/40 bg-amber-500/15 text-amber-300"
                : "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
            )}
          >
            {isElevatedRisk ? <ShieldAlert className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-base font-bold text-white">{copy.nextStepsTitle}</h3>
              <Badge tone={isElevatedRisk ? "warning" : "success"}>
                {copy.riskLevelLabel[result.riskLevel]}
              </Badge>
              <Badge tone="neutral">{copy.generalAdviceBadge}</Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{copy.nextStepsSubtitle}</p>
          </div>
        </div>
      </div>

      {/* Translated Summary when a non-English language is selected */}
      {selectedLanguage !== "en" && (
        <div
          className="rounded-xl border border-cyan-500/25 bg-cyan-950/20 p-3.5 space-y-2"
          data-testid="translated-explanation-box"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-cyan-300 flex items-center gap-1.5">
              <Languages className="h-3.5 w-3.5" />
              {copy.indicatorHeading}
            </span>
            <Badge tone="info">{copy.verdictLabel[result.prediction]}</Badge>
          </div>
          <ul className="space-y-1.5 text-xs text-slate-200">
            {result.indicators.slice(0, 5).map((ind, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>{translateIndicatorToLanguage(ind, selectedLanguage)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Actionable Checklist ("What should I do next?") */}
      <div className="space-y-2.5">
        <p className="text-xs font-mono uppercase tracking-wider text-slate-400">
          Recommended Protective Actions ({isElevatedRisk ? "Do Not Engage / High Caution" : "Standard Vigilance"})
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {actions.map((step, idx) => (
            <div
              key={idx}
              className="flex items-start gap-2.5 rounded-lg border border-slate-800/90 bg-slate-950/60 p-3 text-xs text-slate-200 leading-relaxed"
            >
              {isElevatedRisk ? (
                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              )}
              <span>{step}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Official Cybercrime Reporting Portals with Region Selector */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div>
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-cyan-400" />
              <h4 className="text-sm font-semibold text-white">{copy.reportingTitle}</h4>
              <Badge tone="info">{copy.officialPortalBadge}</Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{copy.reportingSubtitle}</p>
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="reporting-country-select" className="text-xs text-slate-400 whitespace-nowrap">
              Country / Region:
            </label>
            <select
              id="reporting-country-select"
              data-testid="reporting-country-select"
              value={selectedCountryCode}
              onChange={(e) => setSelectedCountryCode(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-white focus:border-cyan-500 focus:outline-none"
            >
              {COUNTRY_REPORTING_CHANNELS.map((c) => (
                <option key={c.code} value={c.code}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Selected Country Official Reporting Details */}
        <div className="grid gap-3 md:grid-cols-3 rounded-lg border border-slate-800/90 bg-slate-900/70 p-3.5">
          <div className="md:col-span-2 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold text-cyan-300">{activeCountry.portalName}</span>
              <span className="text-[11px] text-slate-400">({activeCountry.agencyName})</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{activeCountry.emergencyNote}</p>
            <div className="pt-1 flex flex-wrap items-center gap-3">
              <a
                href={activeCountry.portalUrl}
                target="_blank"
                rel="noopener noreferrer"
                data-testid="official-portal-link"
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/15 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/25 transition"
              >
                <span>Open Official Portal ({activeCountry.portalUrl})</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>

          <div className="flex flex-col justify-center rounded-lg border border-rose-500/30 bg-rose-950/25 p-3">
            <div className="flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-rose-300">
              <PhoneCall className="h-3.5 w-3.5" />
              <span>National Cyber Helpline</span>
            </div>
            <p
              className="text-xl font-bold text-white tracking-tight mt-1"
              data-testid="official-helpline-number"
            >
              {activeCountry.helpline}
            </p>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {activeCountry.code === "IN"
                ? "India 24×7 Toll-Free Financial Cyber Fraud Helpline"
                : `${activeCountry.name} Official Fraud Reporting Line`}
            </p>
          </div>
        </div>

        {/* Strict Non-Auto-Filing Disclaimer */}
        <div className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/90 px-3 py-2 text-[11px] text-slate-400">
          <HelpCircle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
          <span>{copy.noAutoReportDisclaimer}</span>
        </div>
      </div>
    </Card>
  );
}
