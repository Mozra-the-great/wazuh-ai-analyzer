import { describe, expect, it } from 'vitest';
import { clip, formatConfidence, formatDuration, parseTime, percent, secondsUntil } from './format.ts';

describe('format', () => {
  it('treats a time without an offset as UTC', () => {
    expect(parseTime('2026-11-25T10:00:00')?.toISOString()).toBe('2026-11-25T10:00:00.000Z');
    expect(parseTime('2026-11-25T10:00:00+01:00')?.toISOString()).toBe('2026-11-25T09:00:00.000Z');
    expect(parseTime('nonsense')).toBeNull();
    expect(parseTime('')).toBeNull();
    expect(parseTime(null)).toBeNull();
  });

  it('formats durations', () => {
    expect(formatDuration(0)).toBe('bald');
    expect(formatDuration(-4)).toBe('bald');
    expect(formatDuration(42)).toBe('42 s');
    expect(formatDuration(185)).toBe('3 min 05 s');
    expect(formatDuration(7800)).toBe('2 h 10 min');
  });

  it('counts down to a retry time and never below zero', () => {
    const now = Date.parse('2026-11-25T10:00:00Z');
    expect(secondsUntil('2026-11-25T10:01:05Z', now)).toBe(65);
    expect(secondsUntil('2026-11-25T09:00:00Z', now)).toBe(0);
    expect(secondsUntil(null, now)).toBeNull();
  });

  it('computes percentages safely', () => {
    expect(percent(1, 4)).toBe(25);
    expect(percent(5, 4)).toBe(100);
    expect(percent(1, 0)).toBe(0);
    expect(percent(-1, 4)).toBe(0);
  });

  it('formats confidence and clips long texts', () => {
    expect(formatConfidence(0.756)).toBe('76 %');
    expect(formatConfidence(7)).toBe('100 %');
    expect(formatConfidence(null)).toBeNull();
    expect(clip('abcdef', 3)).toBe('abc…');
    expect(clip('abc', 3)).toBe('abc');
  });
});
