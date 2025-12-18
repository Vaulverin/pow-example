package main

func calibrateDifficulty(active int64) uint8 {
	if active <= 1 {
		return 0
	}
	d := int(active-1)*10 + max(0, int(active-10)*int(active-10))
	return uint8(min(d, 200))
}
