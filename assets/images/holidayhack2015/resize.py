from PIL import Image
from resizeimage import resizeimage

for i in xrange(7, 12):
    with open('supergnome_web{}.png'.format(i), 'rb') as f:
        image = Image.open(f)
        cover = resizeimage.resize_cover(image, [600, 200])
        cover.save('supergnome2_web{}.png'.format(i), image.format)
