package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.version.VersionConstraint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VersionConstraintTest {

    @Test
    void exactAndWildcard() {
        assertTrue(VersionConstraint.satisfies("1.2.3", "1.2.3"));
        assertFalse(VersionConstraint.satisfies("1.2.4", "1.2.3"));
        assertTrue(VersionConstraint.satisfies("9.9.9", "*"));
        assertTrue(VersionConstraint.satisfies("9.9.9", ""));
    }

    @Test
    void comparators() {
        assertTrue(VersionConstraint.satisfies("2.0.0", ">=1.0.0"));
        assertFalse(VersionConstraint.satisfies("0.9.0", ">=1.0.0"));
        assertTrue(VersionConstraint.satisfies("1.0.0", ">=1.0.0"));
        assertTrue(VersionConstraint.satisfies("0.9.9", "<1.0.0"));
        assertTrue(VersionConstraint.satisfies("1.5.0", "!=1.4.0"));
    }

    @Test
    void rangesAndIntersection() {
        assertTrue(VersionConstraint.satisfies("1.0.0", "[1.0.0,2.0.0)"));
        assertTrue(VersionConstraint.satisfies("1.9.9", "[1.0.0,2.0.0)"));
        assertFalse(VersionConstraint.satisfies("2.0.0", "[1.0.0,2.0.0)"));
        assertTrue(VersionConstraint.satisfies("2.0.0", "[1.0.0,2.0.0]"));
        assertTrue(VersionConstraint.satisfies("1.5.0", ">=1.0.0,<2.0.0"));
        assertFalse(VersionConstraint.satisfies("2.0.0", ">=1.0.0,<2.0.0"));
    }

    @Test
    void prefixWildcard() {
        assertTrue(VersionConstraint.satisfies("1.2.9", "1.2.*"));
        assertTrue(VersionConstraint.satisfies("1.2.9", "1.2.x"));
        assertFalse(VersionConstraint.satisfies("1.3.0", "1.2.*"));
    }

    @Test
    void snapshotIsLowerThanRelease() {
        assertTrue(VersionConstraint.satisfies("1.0.0-SNAPSHOT", "<1.0.0"));
        assertFalse(VersionConstraint.satisfies("1.0.0", "<1.0.0"));
    }

    @Test
    void invalidVersionThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> VersionConstraint.satisfies("not-a-version", ">=1.0"));
        assertThrows(IllegalArgumentException.class,
                () -> VersionConstraint.satisfies("", "*"));
    }
}
