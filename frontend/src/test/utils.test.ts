import { describe, expect, it } from 'vitest';
import { cn, fmtBytes, fmtInt, fmtPct, shortIp, timeAgo } from '@/lib/utils';

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('a', 'b')).toBe('a b');
    expect(cn('p-2', 'p-4')).toBe('p-4'); // tailwind-merge keeps last
  });
});

describe('fmtInt', () => {
  it('formats numbers with separators', () => {
    expect(fmtInt(1234567)).toBe('1,234,567');
  });
  it('handles null/undefined/NaN', () => {
    expect(fmtInt(null)).toBe('—');
    expect(fmtInt(undefined)).toBe('—');
    expect(fmtInt(NaN)).toBe('—');
  });
});

describe('fmtPct', () => {
  it('renders percentage with one digit by default', () => {
    expect(fmtPct(0.9988)).toBe('99.9%');
    expect(fmtPct(0.5, 2)).toBe('50.00%');
  });
});

describe('fmtBytes', () => {
  it('scales units', () => {
    expect(fmtBytes(0)).toBe('0 B');
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(2048)).toBe('2.0 KB');
    expect(fmtBytes(5 * 1024 * 1024)).toBe('5.0 MB');
  });
});

describe('timeAgo', () => {
  it('handles missing input', () => {
    expect(timeAgo(null)).toBe('—');
    expect(timeAgo(undefined)).toBe('—');
  });
  it('renders seconds ago for recent timestamps', () => {
    const iso = new Date(Date.now() - 30_000).toISOString();
    expect(timeAgo(iso)).toMatch(/s ago$/);
  });
});

describe('shortIp', () => {
  it('truncates long values', () => {
    expect(shortIp('')).toBe('—');
    expect(shortIp('192.168.1.100')).toBe('192.168.1.100');
    expect(shortIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toContain('…');
  });
});
