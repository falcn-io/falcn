package detector

// jaroWinklerSimilarity calculates the Jaro-Winkler similarity between two strings
func (etd *EnhancedTyposquattingDetector) jaroWinklerSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	m, t, l := etd.jaroMatches(s1, s2)
	if m == 0 {
		return 0.0
	}

	j := (float64(m)/float64(len(s1)) + float64(m)/float64(len(s2)) + (float64(m)-float64(t))/float64(m)) / 3.0

	// Winkler modification
	// l is length of common prefix (max 4)
	p := 0.1 // Standard scaling factor
	jw := j + float64(l)*p*(1.0-j)

	return jw
}

func (etd *EnhancedTyposquattingDetector) jaroMatches(s1, s2 string) (int, int, int) {
	r1, r2 := []rune(s1), []rune(s2)
	l1, l2 := len(r1), len(r2)

	matchDistance := (etd.max(l1, l2) / 2) - 1
	if matchDistance < 0 {
		matchDistance = 0
	}

	s1Matches := make([]bool, l1)
	s2Matches := make([]bool, l2)

	matches := 0
	for i := 0; i < l1; i++ {
		start := etd.max(0, i-matchDistance)
		end := etd.min(i+matchDistance+1, l2)

		for j := start; j < end; j++ {
			if s2Matches[j] {
				continue
			}
			if r1[i] == r2[j] {
				s1Matches[i] = true
				s2Matches[j] = true
				matches++
				break
			}
		}
	}

	if matches == 0 {
		return 0, 0, 0
	}

	transpositions := 0
	k := 0
	for i := 0; i < l1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if r1[i] != r2[k] {
			transpositions++
		}
		k++
	}

	// Common prefix length (max 4)
	prefix := 0
	for i := 0; i < etd.min(l1, l2); i++ {
		if r1[i] == r2[i] {
			prefix++
		} else {
			break
		}
		if prefix == 4 {
			break
		}
	}

	return matches, transpositions / 2, prefix
}

// sorensenDiceSimilarity calculates the Sorensen-Dice coefficient based on bigrams
func (etd *EnhancedTyposquattingDetector) sorensenDiceSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) < 2 || len(s2) < 2 {
		return 0.0
	}

	bigrams1 := etd.getBigrams(s1)
	bigrams2 := etd.getBigrams(s2)

	intersection := 0
	for b1 := range bigrams1 {
		if _, ok := bigrams2[b1]; ok {
			intersection++
		}
	}

	return 2.0 * float64(intersection) / float64(len(bigrams1)+len(bigrams2))
}

func (etd *EnhancedTyposquattingDetector) getBigrams(s string) map[string]struct{} {
	bigrams := make(map[string]struct{})
	runes := []rune(s)
	for i := 0; i < len(runes)-1; i++ {
		bigrams[string(runes[i:i+2])] = struct{}{}
	}
	return bigrams
}

func (etd *EnhancedTyposquattingDetector) min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
