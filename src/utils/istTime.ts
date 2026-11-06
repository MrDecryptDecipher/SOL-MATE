/**
 * SOL-MATE — Indian Standard Time (IST / Asia/Kolkata, UTC+05:30) Formatting & Greeting Engine
 * Ensures all database logs, user sessions, and persistent Solana Knowledge Graph records
 * carry deterministic IST timestamps.
 */

export function formatToIST(dateOrEpochMs?: Date | number | null): string {
  const date =
    dateOrEpochMs instanceof Date
      ? dateOrEpochMs
      : typeof dateOrEpochMs === 'number' && !Number.isNaN(dateOrEpochMs)
      ? new Date(dateOrEpochMs)
      : new Date();

  try {
    const formatter = new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    });

    const parts = formatter.formatToParts(date);
    const getPart = (type: string) => parts.find((p) => p.type === type)?.value || '00';
    const day = getPart('day');
    const month = getPart('month');
    const year = getPart('year');
    const hour = getPart('hour');
    const minute = getPart('minute');
    const second = getPart('second');
    const dayPeriod = getPart('dayPeriod').toUpperCase() || 'AM';

    // Standard Indian Date & Time: DD/MM/YYYY, hh:mm:ss AM/PM IST
    return `${day}/${month}/${year}, ${hour}:${minute}:${second} ${dayPeriod} IST`;
  } catch {
    const istOffsetMs = 5.5 * 60 * 60 * 1000;
    const istDate = new Date(date.getTime() + istOffsetMs);
    const iso = istDate.toISOString().replace('T', ' ').slice(0, 19);
    return `${iso} IST`;
  }
}

export function formatIndianDate(dateOrEpochMs?: Date | number | null): string {
  const date =
    dateOrEpochMs instanceof Date
      ? dateOrEpochMs
      : typeof dateOrEpochMs === 'number' && !Number.isNaN(dateOrEpochMs)
      ? new Date(dateOrEpochMs)
      : new Date();

  try {
    return new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
    }).format(date);
  } catch {
    return formatToIST(date).split(',')[0];
  }
}

export function formatIndianTime(dateOrEpochMs?: Date | number | null): string {
  const date =
    dateOrEpochMs instanceof Date
      ? dateOrEpochMs
      : typeof dateOrEpochMs === 'number' && !Number.isNaN(dateOrEpochMs)
      ? new Date(dateOrEpochMs)
      : new Date();

  try {
    const timeStr = new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    }).format(date);
    return `${timeStr} IST`;
  } catch {
    return 'IST';
  }
}

export function formatUnixSecondsToIST(unixSeconds?: number | null): string {
  if (!unixSeconds || unixSeconds <= 0) {
    return formatToIST(Date.now());
  }
  return formatToIST(unixSeconds * 1000);
}

export function getISTGreeting(userName?: string): {
  salutation: string;
  timeOfDayGreeting: string;
  fullWish: string;
  currentIST: string;
} {
  const now = new Date();
  let hourIST = 12;

  try {
    const hourStr = new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      hour: '2-digit',
      hour12: false,
    }).format(now);
    hourIST = parseInt(hourStr, 10);
  } catch {
    const utcHours = now.getUTCHours() + now.getUTCMinutes() / 60;
    hourIST = Math.floor((utcHours + 5.5) % 24);
  }

  let timeOfDayGreeting = 'Good Day';
  if (hourIST >= 5 && hourIST < 12) {
    timeOfDayGreeting = 'Good Morning';
  } else if (hourIST >= 12 && hourIST < 17) {
    timeOfDayGreeting = 'Good Afternoon';
  } else if (hourIST >= 17 && hourIST < 22) {
    timeOfDayGreeting = 'Good Evening';
  } else {
    timeOfDayGreeting = 'Good Evening';
  }

  const cleanName = (userName || 'Analyst').trim();
  const currentIST = formatToIST(now);

  return {
    salutation: `Namaste & ${timeOfDayGreeting}, ${cleanName}!`,
    timeOfDayGreeting,
    fullWish: `Welcome to SOL-MATE Institutional Command. Your Google Account is verified and all Solana forensic telemetry is actively training your Persistent Knowledge Graph (${currentIST}).`,
    currentIST,
  };
}
