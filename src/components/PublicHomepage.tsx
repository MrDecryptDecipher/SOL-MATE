/**
 * SOL-MATE — Public Institutional Homepage & Real Google OAuth Authentication Gateway
 * Presents SOL-MATE's forensic architecture, live IST clock, client IP detection,
 * Ease Mode vs. Pro Mode showcase, and strict Google OAuth authentication (Firebase Popup,
 * Google Identity Services ID-Token Credential, or OAuth Redirect) that logs Name, Email & IP to Firestore.
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheck,
  Lock,
  ArrowRight,
  GitBranch,
  Database,
  Clock,
  Globe,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ExternalLink,
  KeyRound,
  Cpu,
} from 'lucide-react';
import {
  connectWithGoogleOAuth,
  connectWithGoogleIdTokenCredential,
  connectWithGoogleRedirect,
  fetchClientIpDetails,
  GOOGLE_OAUTH_CLIENT_ID,
  ConnectedUserProfile,
  WorkspaceMode,
} from '../services/firebaseService';
import { formatToIST } from '../utils/istTime';
import { SANDEEP_PHOTO_BASE64 } from '../constants/creatorPhotoBase64';

interface PublicHomepageProps {
  onAuthenticated: (user: ConnectedUserProfile) => void;
  existingUser?: ConnectedUserProfile | null;
  onReturnToWorkspace?: () => void;
}

declare global {
  interface Window {
    google?: {
      accounts?: {
        id?: {
          initialize: (config: {
            client_id: string;
            callback: (response: { credential?: string }) => void;
            auto_select?: boolean;
            cancel_on_tap_outside?: boolean;
          }) => void;
          renderButton: (
            parent: HTMLElement,
            options: {
              theme?: 'outline' | 'filled_blue' | 'filled_black';
              size?: 'large' | 'medium' | 'small';
              width?: number | string;
              text?: 'signin_with' | 'signup_with' | 'continue_with' | 'signin';
              shape?: 'rectangular' | 'pill' | 'circle' | 'square';
            }
          ) => void;
          prompt?: () => void;
        };
        oauth2?: {
          initTokenClient: (config: {
            client_id: string;
            scope: string;
            prompt?: string;
            callback: (response: { access_token?: string; error?: string }) => void;
          }) => {
            requestAccessToken: () => void;
          };
        };
      };
    };
  }
}

export const PublicHomepage: React.FC<PublicHomepageProps> = ({
  onAuthenticated,
  existingUser,
  onReturnToWorkspace,
}) => {
  const [currentIST, setCurrentIST] = useState<string>(() => formatToIST(Date.now()));
  const [ipInfo, setIpInfo] = useState<{ ipAddress: string; ipDetails: string }>({
    ipAddress: 'Detecting Client IP...',
    ipDetails: 'Resolving network gateway...',
  });
  const [selectedStartMode, setSelectedStartMode] = useState<WorkspaceMode>('ease');
  const [isConnecting, setIsConnecting] = useState(false);
  const [authStatusNote, setAuthStatusNote] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [previewModeTab, setPreviewModeTab] = useState<'ease' | 'pro'>('ease');

  const gsiButtonRef = useRef<HTMLDivElement | null>(null);
  const selectedModeRef = useRef<WorkspaceMode>(selectedStartMode);
  selectedModeRef.current = selectedStartMode;

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIST(formatToIST(Date.now()));
    }, 1000);
    fetchClientIpDetails().then((info) => setIpInfo(info));
    return () => clearInterval(timer);
  }, []);

  // Load Google Identity Services (GSI) script so users can also authenticate via embedded Google Credential button
  useEffect(() => {
    if (!GOOGLE_OAUTH_CLIENT_ID || typeof window === 'undefined') return;

    const initGsi = () => {
      if (!window.google?.accounts?.id || !gsiButtonRef.current) return;
      try {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_OAUTH_CLIENT_ID,
          callback: async (response) => {
            if (!response.credential) return;
            setIsConnecting(true);
            setAuthError(null);
            setAuthStatusNote(
              'Verifying Google Identity Token with Firebase Auth & logging Name, Email & IP to Firestore...'
            );
            try {
              const profile = await connectWithGoogleIdTokenCredential(
                response.credential,
                selectedModeRef.current
              );
              onAuthenticated(profile);
            } catch (err: any) {
              setAuthError(
                err?.message || 'Failed to exchange Google credential with Firebase Auth.'
              );
              setAuthStatusNote(null);
            } finally {
              setIsConnecting(false);
            }
          },
          auto_select: false,
          cancel_on_tap_outside: true,
        });

        gsiButtonRef.current.innerHTML = '';
        window.google.accounts.id.renderButton(gsiButtonRef.current, {
          theme: 'filled_black',
          size: 'large',
          width: 340,
          text: 'continue_with',
          shape: 'rectangular',
        });
      } catch {
        // ignore GSI init error
      }
    };

    const existingScript = document.getElementById('google-gsi-client-script');
    if (existingScript) {
      initGsi();
      return;
    }

    const script = document.createElement('script');
    script.id = 'google-gsi-client-script';
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = initGsi;
    document.head.appendChild(script);
  }, [onAuthenticated]);

  const handleGooglePopupConnect = async () => {
    setIsConnecting(true);
    setAuthError(null);
    setAuthStatusNote('Opening Google OAuth window & capturing client IP telemetry...');
    try {
      const profile = await connectWithGoogleOAuth(selectedStartMode);
      onAuthenticated(profile);
      setIsConnecting(false);
    } catch (err: any) {
      const code = err?.code || '';
      if (
        (code === 'auth/unauthorized-domain' ||
          code === 'auth/operation-not-supported-in-this-environment') &&
        window.google?.accounts?.oauth2 &&
        GOOGLE_OAUTH_CLIENT_ID
      ) {
        setAuthStatusNote('Opening Google Identity OAuth 2.0 Consent Window...');
        try {
          const tokenClient = window.google.accounts.oauth2.initTokenClient({
            client_id: GOOGLE_OAUTH_CLIENT_ID,
            scope: 'openid email profile',
            prompt: 'select_account',
            callback: async (tokenResponse) => {
              if (tokenResponse.error || !tokenResponse.access_token) {
                setAuthError(
                  `Google OAuth cancelled or failed: ${tokenResponse.error || 'No access token'}`
                );
                setAuthStatusNote(null);
                setIsConnecting(false);
                return;
              }
              try {
                const profile = await connectWithGoogleIdTokenCredential(
                  null,
                  selectedModeRef.current,
                  tokenResponse.access_token
                );
                onAuthenticated(profile);
              } catch (credErr: any) {
                setAuthError(
                  credErr?.message || 'Failed to exchange Google OAuth token with Firebase.'
                );
              } finally {
                setAuthStatusNote(null);
                setIsConnecting(false);
              }
            },
          });
          tokenClient.requestAccessToken();
          return;
        } catch {
          // fall through
        }
      }

      if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
        setAuthError(
          'Google Sign-In popup was closed before completing authentication. Please click "Sign in with Google Account" again and select your Google account.'
        );
      } else if (code === 'auth/popup-blocked') {
        setAuthError(
          'Your browser blocked the Google OAuth popup window. Please allow popups for this site or click "Continue with Google" below.'
        );
      } else {
        setAuthError(
          err?.message ||
            'Google OAuth authentication could not be completed. Please click "Continue with Google" below.'
        );
      }
      setAuthStatusNote(null);
      setIsConnecting(false);
    }
  };

  const handleGoogleRedirectConnect = async () => {
    setIsConnecting(true);
    setAuthError(null);
    setAuthStatusNote('Redirecting to Google OAuth authentication...');
    try {
      await connectWithGoogleRedirect(selectedStartMode);
    } catch (err: any) {
      setAuthError(err?.message || 'Failed to start Google OAuth redirect.');
      setAuthStatusNote(null);
      setIsConnecting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Institutional Navigation Bar */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#07090e]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-5 h-5 text-slate-950" />
            </div>
            <div>
              <span className="text-lg font-extrabold tracking-tight text-white block leading-none">
                SOL<span className="text-cyan-400">-MATE</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                Built by <strong className="text-cyan-300">Sandeep Kumar Sahoo</strong>
              </span>
            </div>
            <img
              src={SANDEEP_PHOTO_BASE64}
              alt="Sandeep Kumar Sahoo"
              className="w-8 h-8 rounded-lg object-cover border border-cyan-400/60 shadow-sm hidden sm:block"
              title="Built by Sandeep Kumar Sahoo (Base64 Embedded)"
            />
          </div>

          <div className="hidden md:flex items-center gap-6 text-xs text-slate-400">
            <a href="#capabilities" className="hover:text-white transition">
              01. Forensic Architecture
            </a>
            <a href="#modes" className="hover:text-white transition">
              02. Ease Mode vs. Pro Mode
            </a>
            <a href="#knowledge-graph" className="hover:text-white transition">
              03. Persistent IST Knowledge Graph
            </a>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#0e1420] border border-slate-800 text-[11px] font-mono text-cyan-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>{currentIST}</span>
            </div>

            {existingUser && onReturnToWorkspace ? (
              <button
                onClick={onReturnToWorkspace}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer"
              >
                <span>Return to Workspace ({existingUser.name.split(' ')[0]})</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            ) : (
              <button
                onClick={handleGooglePopupConnect}
                disabled={isConnecting}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <span>Sign in with Google</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section: Asymmetric 7/5 Grid with Live Google OAuth Gateway */}
      <section className="relative overflow-hidden pt-10 pb-16 sm:pt-14 sm:pb-20 border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-start">
            {/* Left 7 Columns: Value Proposition & Live Institutional Telemetry Proof */}
            <div className="lg:col-span-7 space-y-6 pt-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
                <span>
                  INSTITUTIONAL DIGITAL ASSET RISK & COMPLIANCE • REAL-TIME TRANSACTION ASSURANCE • SOLANA & MULTI-CHAIN
                </span>
              </div>

              <h1 className="text-4xl sm:text-5xl lg:text-[52px] font-extrabold tracking-tight text-white leading-[1.08]">
                Real-Time Transaction Assurance.{' '}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500">
                  Adaptive Risk Intelligence.
                </span>{' '}
                One Institutional Knowledge Graph.
              </h1>

              <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-2xl">
                <strong className="text-white">SOL-MATE</strong> gives institutional treasury, compliance, and digital asset operations teams instant visibility into every on-chain transaction. Built with{' '}
                <strong className="text-cyan-300">
                  adaptive alert intelligence that goes beyond static rulebooks
                </strong>
                , the platform automatically identifies issuance, redemptions, client onboarding, governance changes, settlement flows, and emerging operational risks across any transaction. Every counterparty is verified against our pre-trained{' '}
                <strong className="text-emerald-300">
                  Institutional Counterparty, Tokenized Asset & Smart Contract Whitelist Knowledge Base
                </strong>
                , while building a continuous, audit-ready{' '}
                <strong className="text-cyan-300">IST-timestamped Institutional Knowledge Graph</strong>.
              </p>

              {/* Quantified Proof Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                <div className="p-3.5 rounded-xl bg-[#0c121d] border border-slate-800">
                  <div className="text-xl font-mono font-extrabold text-white">Adaptive</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    360° Alert Intelligence
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-[#0c121d] border border-slate-800">
                  <div className="text-xl font-mono font-extrabold text-emerald-400">37 Entities</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Pre-Trained Whitelist KB
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-[#0c121d] border border-slate-800">
                  <div className="text-xl font-mono font-extrabold text-cyan-400">Ease + Pro</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Executive & Analyst Views
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-[#0c121d] border border-slate-800">
                  <div className="text-xl font-mono font-extrabold text-amber-300">IST (UTC+5:30)</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Audit-Ready Recordkeeping
                  </div>
                </div>
              </div>

              {/* Live Architecture Preview Card */}
              <div className="p-5 rounded-2xl bg-[#0b101a] border border-slate-800/90 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <GitBranch className="w-4 h-4 text-cyan-400" />
                    Live Institutional Verification Pipeline
                  </span>
                  <span className="font-mono text-[11px] text-emerald-400">
                    Issuance • Custody • Settlement Assurance
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                  <div className="p-3 rounded-xl bg-[#070a10] border border-slate-800/80 space-y-1">
                    <div className="text-[10px] font-mono text-cyan-400">STEP 01 • GOOGLE OAUTH</div>
                    <div className="font-bold text-slate-200">Verified Identity + IP Audit</div>
                    <p className="text-[11px] text-slate-400">
                      Authenticates your Google Account via OAuth and records Name, Email & Client IP
                      to Firestore in IST.
                    </p>
                  </div>
                  <div className="p-3 rounded-xl bg-[#070a10] border border-slate-800/80 space-y-1">
                    <div className="text-[10px] font-mono text-emerald-400">
                      STEP 02 • EASE OR PRO TRIAGE
                    </div>
                    <div className="font-bold text-slate-200">Instant Alert & Whitelist Check</div>
                    <p className="text-[11px] text-slate-400">
                      Flags Mint, Burn, StopCodes, Onboarding, Signers, Fee Payers & Whitelist status.
                    </p>
                  </div>
                  <div className="p-3 rounded-xl bg-[#070a10] border border-slate-800/80 space-y-1">
                    <div className="text-[10px] font-mono text-amber-300">
                      STEP 03 • PERSISTENT GRAPH
                    </div>
                    <div className="font-bold text-slate-200">Continuous Solana Training</div>
                    <p className="text-[11px] text-slate-400">
                      Every inspected Solana tx or address trains the shared Knowledge Graph in IST.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Right 5 Columns: Strict Google OAuth Authentication Gateway */}
            <div className="lg:col-span-5">
              <div className="bg-[#0d1320] border border-cyan-500/40 rounded-2xl p-6 shadow-2xl shadow-cyan-950/30 space-y-5 relative overflow-hidden">
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-400 via-blue-500 to-emerald-400" />

                <div className="space-y-1">
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-bold uppercase text-cyan-400">
                    <Lock className="w-3.5 h-3.5" /> Strict OAuth 2.0 Authentication Gate
                  </span>
                  <h2 className="text-xl font-extrabold text-white">
                    Connect Your Google Account
                  </h2>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Sign in with your Google Account to unlock the SOL-MATE forensic platform. Upon
                    authentication, your verified Google Name, Email, and Client IP are stored to
                    Firestore with IST timestamps.
                  </p>
                </div>

                {/* Live Client IP & IST Telemetry Preview Box */}
                <div className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" /> Detected Client IP:
                    </span>
                    <span className="font-mono font-bold text-emerald-400">
                      {ipInfo.ipAddress}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-amber-400" /> Session Timestamp (IST):
                    </span>
                    <span className="font-mono text-slate-200">{currentIST}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/80 flex items-center justify-between">
                    <span className="truncate">{ipInfo.ipDetails}</span>
                    <span className="font-mono text-[10px] text-cyan-400 shrink-0 ml-2">
                      Firestore Audit Ready
                    </span>
                  </div>
                </div>

                {/* Workspace Mode Selector Before Entering */}
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-wider text-slate-400">
                    Select Initial Workspace Experience After Sign-In
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      onClick={() => setSelectedStartMode('ease')}
                      className={`p-2.5 rounded-xl border text-left transition cursor-pointer ${
                        selectedStartMode === 'ease'
                          ? 'bg-cyan-500/15 border-cyan-400 text-white'
                          : 'bg-[#080c14] border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-extrabold text-cyan-300">EASE</span>
                        {selectedStartMode === 'ease' && (
                          <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                        )}
                      </div>
                      <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                        Executive Copiable Tables &amp; 360° Forensic Graph
                      </p>
                    </button>

                    <button
                      type="button"
                      onClick={() => setSelectedStartMode('instant')}
                      className={`p-2.5 rounded-xl border text-left transition cursor-pointer ${
                        selectedStartMode === 'instant'
                          ? 'bg-amber-500/15 border-amber-400 text-white'
                          : 'bg-[#080c14] border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-extrabold text-amber-300">INSTANT</span>
                        {selectedStartMode === 'instant' && (
                          <CheckCircle2 className="w-3 h-3 text-amber-400" />
                        )}
                      </div>
                      <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                        1s Continuous Whitelist Scanner &amp; Authority Alert
                      </p>
                    </button>

                    <button
                      type="button"
                      onClick={() => setSelectedStartMode('pro')}
                      className={`p-2.5 rounded-xl border text-left transition cursor-pointer ${
                        selectedStartMode === 'pro'
                          ? 'bg-blue-500/15 border-blue-400 text-white'
                          : 'bg-[#080c14] border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-extrabold text-blue-300">PRO</span>
                        {selectedStartMode === 'pro' && (
                          <CheckCircle2 className="w-3 h-3 text-blue-400" />
                        )}
                      </div>
                      <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                        9-Tab Byte Forensics, CPI Execution Tree &amp; 19 Rules
                      </p>
                    </button>
                  </div>
                </div>

                {/* Primary Google OAuth Popup Button */}
                <div className="space-y-3 pt-1">
                  <button
                    type="button"
                    onClick={handleGooglePopupConnect}
                    disabled={isConnecting}
                    className="w-full py-3.5 px-4 rounded-xl bg-white hover:bg-slate-100 text-slate-950 font-extrabold text-sm flex items-center justify-center gap-3 shadow-lg transition cursor-pointer disabled:opacity-60"
                  >
                    {isConnecting ? (
                      <Loader2 className="w-4 h-4 animate-spin text-slate-900" />
                    ) : (
                      <svg className="w-4 h-4" viewBox="0 0 24 24">
                        <path
                          fill="#4285F4"
                          d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
                        />
                        <path
                          fill="#34A853"
                          d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.14C3.26 21.3 7.31 24 12 24z"
                        />
                        <path
                          fill="#FBBC05"
                          d="M5.28 14.24c-.24-.72-.38-1.49-.38-2.24s.14-1.52.38-2.24V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.99-3.14z"
                        />
                        <path
                          fill="#EA4335"
                          d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.99 3.14c.95-2.85 3.6-4.96 6.72-4.96z"
                        />
                      </svg>
                    )}
                    <span>
                      Sign in with Google Account ({selectedStartMode === 'ease' ? 'Ease Mode' : 'Pro Mode'})
                    </span>
                  </button>

                  {/* Embedded Google Identity Services (GSI) Button Container */}
                  <div className="flex flex-col items-center justify-center">
                    <div ref={gsiButtonRef} className="min-h-[40px] flex items-center justify-center" />
                  </div>

                  {/* Secondary OAuth Redirect Option for Strict Popup-Blocking Browsers */}
                  <button
                    type="button"
                    onClick={handleGoogleRedirectConnect}
                    disabled={isConnecting}
                    className="w-full py-2.5 px-4 rounded-xl bg-[#080c14] hover:bg-[#111827] border border-slate-700/80 text-slate-300 hover:text-white font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-50"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Browser blocking popups? Continue via Google OAuth Redirect</span>
                  </button>
                </div>

                {authStatusNote && (
                  <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs text-cyan-300 font-mono flex items-center gap-2">
                    <Loader2 className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
                    <span>{authStatusNote}</span>
                  </div>
                )}

                {authError && (
                  <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/40 text-xs text-rose-300 space-y-1">
                    <div className="font-bold flex items-center gap-1.5 text-rose-200">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>Google Authentication Required</span>
                    </div>
                    <p className="text-[11px] leading-relaxed">{authError}</p>
                  </div>
                )}

                {/* Database Audit Security Guarantee */}
                <div className="pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] text-slate-400">
                  <div className="flex items-center justify-between font-mono">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                      Zero-Bypass OAuth 2.0 Verification
                    </span>
                    <span className="text-emerald-400">Firestore Security Rules v2</span>
                  </div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">
                    Only verified Google OAuth tokens issued for your Google account are accepted.
                    All user activity and trained Solana Knowledge Graph nodes are stored with IST (
                    <code className="text-cyan-400">Asia/Kolkata</code>) timestamps.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 01: Asymmetric Bento Grid of Core Forensic Capabilities */}
      <section id="capabilities" className="py-16 border-b border-slate-800/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 space-y-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <div className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                01. Institutional Capabilities
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
                Built for Institutional Digital Assets, Token-2022 & Multi-Chain Compliance
              </h2>
            </div>
            <p className="text-xs text-slate-400 max-w-md">
              Every action you take inside SOL-MATE is logged to your user database record while
              every Solana transaction trains the persistent IST Knowledge Graph.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Span 2: Adaptive Institutional Alert & Risk Intelligence */}
            <div className="md:col-span-2 p-6 rounded-2xl bg-[#0b101b] border border-slate-800 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-emerald-400">
                    01. ADAPTIVE TRANSACTION ALERT & RISK INTELLIGENCE
                  </span>
                  <span className="px-2.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-[10px] font-mono text-emerald-300">
                    ANY ASSET • ANY WORKFLOW • REAL-TIME ASSURANCE
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white">
                  Beyond Fixed Rulebooks — Captures Any Operational, Compliance, or Financial Event
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Traditional monitoring tools only flag a narrow list of pre-configured events.
                  SOL-MATE evaluates the complete business context of every transaction—automatically
                  identifying token issuance, redemptions, client custody onboarding, transfer
                  compliance checks, administrative privilege updates, and unexpected counterparty
                  activity across both standard and custom institutional workflows.
                </p>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
                {[
                  { label: 'Issuance & Redemptions', rule: 'TREASURY OPS', color: 'text-emerald-300 border-emerald-500/30' },
                  { label: 'Transfer Compliance', rule: 'POLICY CONTROLS', color: 'text-cyan-300 border-cyan-500/30' },
                  { label: 'Custody & Onboarding', rule: 'CLIENT LIFECYCLE', color: 'text-amber-300 border-amber-500/30' },
                  { label: 'Governance & Risk', rule: 'ANOMALY GUARD', color: 'text-rose-300 border-rose-500/30' },
                ].map((item) => (
                  <div
                    key={item.rule}
                    className={`p-2.5 rounded-xl bg-[#070a10] border ${item.color} font-mono text-xs`}
                  >
                    <div className="text-[10px] opacity-75">{item.rule}</div>
                    <div className="font-bold mt-0.5">{item.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Span 1: Pre-Seeded Institutional Counterparty & Whitelist Knowledge Base */}
            <div className="p-6 rounded-2xl bg-[#0b101b] border border-slate-800 flex flex-col justify-between space-y-4">
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  02. INSTITUTIONAL COUNTERPARTY & WHITELIST REGISTRY
                </span>
                <h3 className="text-lg font-bold text-white">
                  Verified Counterparty, Program & Signer Governance Directory
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Pre-trained with authorized institutional tokenization programs, transfer
                  compliance hooks, treasury & token administrators, redemption vaults, regulated
                  asset mints, and verified Smart Contract Account (SCA) ↔ Signer (EOA) pairs.
                </p>
              </div>
              <div className="p-3 rounded-xl bg-[#070a10] border border-slate-800 space-y-1.5 font-mono text-[11px]">
                <div className="flex items-center justify-between text-emerald-300">
                  <span>Core Governance & Compliance Programs</span>
                  <span className="font-bold">VERIFIED</span>
                </div>
                <div className="flex items-center justify-between text-emerald-300">
                  <span>Regulated Institutional Asset Suites</span>
                  <span className="font-bold">VERIFIED</span>
                </div>
                <div className="flex items-center justify-between text-cyan-300">
                  <span>Authorized SCA ↔ EOA Signer Pairs</span>
                  <span className="font-bold">VERIFIED</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 02: Ease Mode vs. Pro Mode Interactive Comparison */}
      <section id="modes" className="py-16 border-b border-slate-800/80 bg-[#080b12]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 space-y-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                02. Dual-Experience Architecture
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
                Switch Seamlessly Between Ease Mode & Pro Mode
              </h2>
            </div>

            <div className="inline-flex items-center bg-[#0d1320] p-1 rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => setPreviewModeTab('ease')}
                className={`px-4 py-2 rounded-lg text-xs font-extrabold transition cursor-pointer ${
                  previewModeTab === 'ease'
                    ? 'bg-cyan-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                EASE MODE (Executive A-B-C-D)
              </button>
              <button
                type="button"
                onClick={() => setPreviewModeTab('pro')}
                className={`px-4 py-2 rounded-lg text-xs font-extrabold transition cursor-pointer ${
                  previewModeTab === 'pro'
                    ? 'bg-blue-500 text-slate-950'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                PRO MODE (9-Tab Deep Forensics)
              </button>
            </div>
          </div>

          {previewModeTab === 'ease' ? (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-cyan-400">STEP A • INPUT</span>
                <h4 className="text-base font-bold text-white">Paste Solana Tx or Address</h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Enter any Solana Base58 transaction signature, fetch live Mainnet signatures from
                  any wallet/mint, or select a verified replay scenario.
                </p>
              </div>
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-emerald-400">
                  STEP B • ALERT TYPE
                </span>
                <h4 className="text-base font-bold text-white">
                  Mint, Burn, StopCodes or Onboarding
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Instantly identifies the exact alert classification, rule IDs, byte discriminators,
                  and whether a new client custody account was onboarded.
                </p>
              </div>
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-amber-300">
                  STEP C • VALUE & WHITELIST
                </span>
                <h4 className="text-base font-bold text-white">
                  Signers, Fee Payer, Flow & 10-Vector Scam Check
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Shows total value involved, signers, fee payers, interactive whitelist management,
                  From → To flow of funds, and 10-vector scam/anomaly checks.
                </p>
              </div>
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-violet-300">
                  STEP D • KNOWLEDGE GRAPH
                </span>
                <h4 className="text-base font-bold text-white">
                  Correlated Lifecycle vs. Independent
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Renders an interactive Knowledge Graph of correlated lifecycle stages or isolates
                  independent standalone alerts with IST timestamps.
                </p>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-blue-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-blue-400">
                  9-TAB INVESTIGATION WORKSPACE
                </span>
                <h4 className="text-base font-bold text-white">
                  Complete CPI Execution Tree & Byte Forensics
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Inspect nested Cross-Program Invocations, 8-byte Anchor discriminators, state
                  transitions, authorities, and raw RPC evidence proofs.
                </p>
              </div>
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-blue-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-emerald-400">
                  UNIVERSAL ALERT INBOX & 19-RULE CONSOLE
                </span>
                <h4 className="text-base font-bold text-white">
                  Analyst Dispositions & Precision/Recall Metrics
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Triage alerts across Solana & EVM, tune thresholds, and run replay benchmarks
                  across all 7 risk domains (A–G).
                </p>
              </div>
              <div className="p-5 rounded-2xl bg-[#0c121e] border border-blue-500/30 space-y-2">
                <span className="text-xs font-mono font-bold text-amber-300">
                  LIVE PARALLEL WSS STREAMING
                </span>
                <h4 className="text-base font-bold text-white">
                  Real-Time Program & Token-2022 Monitoring
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Stream live Mainnet invocations with controlled cadence buffering and automatic
                  arbitrage-revert filtering.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Section 03: Persistent IST Knowledge Graph Overview & Quiet Footer */}
      <section id="knowledge-graph" className="py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="p-6 sm:p-8 rounded-2xl bg-gradient-to-r from-[#0c1322] via-[#0f1829] to-[#0c1322] border border-cyan-500/30 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="space-y-2 max-w-2xl">
              <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
                <Database className="w-4 h-4" />
                <span>PERSISTENT DATABASE & IST SOLANA KNOWLEDGE GRAPH</span>
              </div>
              <h3 className="text-xl sm:text-2xl font-extrabold text-white">
                Every Solana Interaction Trains Your Institutional Knowledge Graph in IST
              </h3>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                Sign in with your Google Account above to start investigating. Your user profile,
                email, client IP, product actions, and all trained Solana entities are persisted to
                Firestore with Indian Standard Time (<code className="text-cyan-300">Asia/Kolkata</code>)
                timestamps.
              </p>
            </div>

            <button
              type="button"
              onClick={handleGooglePopupConnect}
              disabled={isConnecting}
              className="px-6 py-3.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-extrabold text-xs sm:text-sm flex items-center gap-2 shadow-lg shadow-cyan-500/20 shrink-0 cursor-pointer"
            >
              <span>Sign in with Google Account</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </section>

      <footer className="border-t border-slate-900 py-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-4 h-4 text-cyan-500 shrink-0" />
            <span className="font-bold text-slate-300">SOL-MATE v2.5</span>
            <span>— Institutional Solana & Multi-Chain Forensics Platform</span>
          </div>

          {/* Built by Sandeep Kumar Sahoo Badge with Base64 Photo */}
          <div className="flex items-center gap-3 px-3.5 py-2 rounded-xl bg-[#0c121e] border border-cyan-500/30">
            <img
              src={SANDEEP_PHOTO_BASE64}
              alt="Sandeep Kumar Sahoo"
              className="w-10 h-10 rounded-xl object-cover border-2 border-cyan-400/70 shadow-md shadow-cyan-500/20 shrink-0"
            />
            <div className="text-left">
              <div className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                SOL-MATE FORENSICS ARCHITECT
              </div>
              <div className="text-xs text-slate-300">
                Built by <span className="text-white font-extrabold">Sandeep Kumar Sahoo</span>
              </div>
            </div>
          </div>

          <div className="font-mono text-[11px] text-slate-400">
            All Database & Knowledge Graph Telemetry Timestamped in IST (Asia/Kolkata • UTC+05:30)
          </div>
        </div>
      </footer>
    </div>
  );
};
