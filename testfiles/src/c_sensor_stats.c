#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    double samples[16];
    size_t count;
} sensor_series;

static double clamp(double value, double min, double max) {
    if (value < min) {
        return min;
    }
    if (value > max) {
        return max;
    }
    return value;
}

static double average(const sensor_series *series) {
    if (series->count == 0) {
        return 0.0;
    }
    double total = 0.0;
    for (size_t i = 0; i < series->count; ++i) {
        total += series->samples[i];
    }
    return total / (double)series->count;
}

static double variance(const sensor_series *series, double mean) {
    if (series->count < 2) {
        return 0.0;
    }
    double total = 0.0;
    for (size_t i = 0; i < series->count; ++i) {
        double delta = series->samples[i] - mean;
        total += delta * delta;
    }
    return total / (double)(series->count - 1);
}

static bool load_series(sensor_series *series, const char *line) {
    memset(series, 0, sizeof(*series));
    const char *colon = strchr(line, ':');
    if (!colon) {
        return false;
    }
    size_t name_len = (size_t)(colon - line);
    if (name_len >= sizeof(series->name)) {
        name_len = sizeof(series->name) - 1;
    }
    memcpy(series->name, line, name_len);
    series->name[name_len] = '\0';

    const char *cursor = colon + 1;
    while (*cursor != '\0' && series->count < 16) {
        char *endptr = NULL;
        double value = strtod(cursor, &endptr);
        if (endptr == cursor) {
            break;
        }
        series->samples[series->count++] = clamp(value, -1000.0, 1000.0);
        if (*endptr == ',') {
            cursor = endptr + 1;
        } else {
            cursor = endptr;
        }
    }

    return series->count > 0;
}

static void print_report(const sensor_series *series) {
    double mean = average(series);
    double variance_value = variance(series, mean);
    double deviation = sqrt(variance_value);

    printf("Series %s -> samples=%zu mean=%.2f stdev=%.2f\n", series->name, series->count, mean, deviation);
}

int main(void) {
    const char *lines[] = {
        "temperature:23.5,24.0,23.8,25.1,22.9",
        "pressure:1012.0,1011.8,1012.4,1013.2",
        "humidity:45.0,47.5,50.1,48.3",
    };

    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i) {
        sensor_series series;
        if (load_series(&series, lines[i])) {
            print_report(&series);
        }
    }

    return 0;
}
