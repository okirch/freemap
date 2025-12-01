/*
 * Copyright (C) 2025 Olaf Kirch <okir@suse.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Based on the Box-Muller transform, generate some semblance of Gaussian noise.
 * Given that we need to do this quite a lot, we pre-generates a table of
 * 65536 randomized outputs for a normal distribution with mu = 1 and sigma = 1.
 *
 * The result can be transformed to any (mu, sigma) by a simple transformation:
 *	X' = sigma * X + mu
 *
 * I'm not sure, however, whether a Gaussian distribution is the correct model.
 * At each router, there is a physical delay of transmitting a packet (which is a
 * function of the packet length), plus the queue delay.
 * The latter is normally not jumping around wildly, but varies gradually
 * over time with the amount of traffic the router sees.
 */


#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

#include "fakenet.h"
#include "logging.h"

#define NSAMPLES	65536
static const double	twopi = 2.0 * M_PI;

struct box_muller_sample {
	double		z0, z1;
};

static struct box_muller_sample	samples[NSAMPLES];

static void
fm_gaussian_init(void)
{
	unsigned int i;

	for (i = 0; i < NSAMPLES; ++i) {
		double u1, u2, mag;

		do {
			u1 = drand48();
		} while (u1 == 0);
		u2 = drand48();

		mag = sqrt(-2.0 * log(u1));
		samples[i].z0 = mag * cos(twopi * u2);
		samples[i].z1 = mag * sin(twopi * u2);
	}
}

double
fm_gaussian(double mu, double sigma)
{
	static bool initialized = false;
	unsigned int k;

	if (!initialized) {
		fm_gaussian_init();
		initialized = true;
	}

	k = ((unsigned int) random()) % NSAMPLES;
	return sigma * samples[k].z0 + mu;
}

double
fm_n_gaussians(unsigned int nsamples, double mu, double sigma)
{
	static bool initialized = false;
	unsigned int k;
	double result = 0, n_times_mu, lthresh, samp;

	if (!initialized) {
		fm_gaussian_init();
		initialized = true;
	}

	lthresh = -mu / sigma;

	n_times_mu = nsamples * mu;

	while (nsamples--) {
		k = ((unsigned int) random()) % NSAMPLES;

		samp = samples[k].z0;
		if (samp < lthresh)
			samp = lthresh;
		result += samp;

		if (false && nsamples) {
			samp = samples[k].z1;
			if (samp < lthresh)
				samp = lthresh;
			result += samp;
			nsamples -= 1;
		}
	}

	return sigma * result + n_times_mu;
}
