export function dateFromIntegerSeconds(seconds: number): Date | undefined {
  const milliseconds = seconds * 1_000;
  if (!Number.isFinite(milliseconds)) return undefined;
  const date = new Date(milliseconds);
  return Number.isFinite(date.getTime()) ? date : undefined;
}
