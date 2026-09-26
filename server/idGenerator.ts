let sequence = 1000;

export function generateId(prefix: string): string {
  sequence += 1;
  const rand = Math.random().toString(36).substring(2, 7);
  return `${prefix}-${Date.now().toString(36)}-${sequence}-${rand}`;
}
