import numpy as np

def save_int_csv(path, obj):
    np.savetxt(path, obj, fmt='%d', delimiter=',')

def save_float_csv(path, obj):
    np.savetxt(path, obj, fmt='%.6f', delimiter=',')

def save_string_csv(path, obj):
    np.savetxt(path, obj, fmt='%s', delimiter=',')


def load_int_csv(path):
    return np.loadtxt(path, dtype=int, delimiter=',')


def load_float_csv(path):
    return np.loadtxt(path, dtype=float, delimiter=',')

def load_string_csv(path):
    return np.loadtxt(path, dtype=str, delimiter=',')