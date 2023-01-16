export function getMatchForIndex(entry: string, regex: RegExp, index = 0) {
	const match = entry.match(regex);
	return match?.[index];
}
