// SPDX-License-Identifier: Apache-2.0
package org.lineageos.pocketinput.settings;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.preference.Preference;
import androidx.preference.PreferenceViewHolder;
import java.util.function.Consumer;
import org.lineageos.pocketinput.DisplayModes;

/**
 * The square modes as a grid: rows are the content size (DisplayModes.SQUARE_DP), columns the
 * render size (SQUARE_RENDER). Each cell previews how much fits at that size and how sharp it is.
 */
public final class SquareGridPreference extends Preference {
    private Consumer<DisplayModes.Mode> mOnPick;
    private String mSelectedId;

    public SquareGridPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
        setLayoutResource(R.layout.preference_square_grid);
    }

    void setOnPick(Consumer<DisplayModes.Mode> onPick) {
        mOnPick = onPick;
    }

    void setSelectedId(String id) {
        if (id.equals(mSelectedId)) return;
        mSelectedId = id;
        notifyChanged();
    }

    @Override public void onBindViewHolder(PreferenceViewHolder holder) {
        super.onBindViewHolder(holder);
        holder.setDividerAllowedAbove(false);
        holder.setDividerAllowedBelow(false);
        Context context = getContext();
        LinearLayout grid = (LinearLayout) holder.findViewById(R.id.square_grid);
        grid.removeAllViews();
        int label = dp(context, 56), gap = dp(context, 4);
        LinearLayout header = row(context);
        header.addView(new View(context), new LinearLayout.LayoutParams(label, 1));
        for (int render : DisplayModes.SQUARE_RENDER) {
            TextView text = text(context, context.getString(R.string.column_render, render));
            text.setGravity(Gravity.CENTER);
            header.addView(text, cell(gap));
        }
        grid.addView(header);
        for (int dp : DisplayModes.SQUARE_DP) {
            LinearLayout row = row(context);
            TextView text = text(context, context.getString(R.string.row_dp, dp));
            text.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
            row.addView(text, new LinearLayout.LayoutParams(label, ViewGroup.LayoutParams.MATCH_PARENT));
            for (int render : DisplayModes.SQUARE_RENDER) {
                DisplayModes.Mode mode = DisplayModes.find(DisplayModes.squareId(dp, render));
                PreviewView preview = new PreviewView(context, dp, render, mode.id.equals(mSelectedId));
                preview.setContentDescription(mode.label);
                preview.setOnClickListener(v -> {
                    if (mOnPick != null) mOnPick.accept(mode);
                });
                row.addView(preview, cell(gap));
            }
            grid.addView(row);
        }
    }

    private static LinearLayout row(Context context) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        return row;
    }

    private static TextView text(Context context, String value) {
        TextView text = new TextView(context);
        text.setText(value);
        text.setTextAppearance(android.R.style.TextAppearance_DeviceDefault_Small);
        TypedArray a = context.obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        text.setTextColor(a.getColorStateList(0));
        a.recycle();
        return text;
    }

    private static LinearLayout.LayoutParams cell(int gap) {
        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        params.setMargins(gap, gap, gap, gap);
        return params;
    }

    static int dp(Context context, float value) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value,
                context.getResources().getDisplayMetrics()));
    }

    /**
     * A mini screen with the same content in every cell (status bar, icon dots, text lines),
     * drawn at 524/contentDp of normal size so a bigger size shows more, smaller items. Lower
     * render sizes draw into a smaller bitmap that is scaled up without filtering, so they look
     * blockier.
     */
    static final class PreviewView extends View {
        private static final float NORMAL_DP = 524;
        private static final float[] WIDTHS = {0.9f, 0.6f, 0.8f, 0.45f, 0.75f, 0.85f, 0.5f};
        private final int mContentDp;
        private final int mRender;
        private final int mMaxSide;
        private final Paint mFrame = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mFill = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mText = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mAccent = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mBitmapPaint = new Paint();
        private final RectF mRect = new RectF();
        private Bitmap mBitmap;

        PreviewView(Context context, int contentDp, int render, boolean selected) {
            super(context);
            mContentDp = contentDp;
            mRender = render;
            mMaxSide = dp(context, 96);
            setClickable(true);
            setFocusable(true);
            setSelected(selected);
            TypedArray a = context.obtainStyledAttributes(new int[]{android.R.attr.colorAccent,
                    android.R.attr.textColorSecondary, android.R.attr.selectableItemBackground,
                    android.R.attr.textColorPrimary});
            int accent = a.getColor(0, 0xff3c6ccf);
            int secondary = a.getColor(1, 0xff777777);
            setBackground(a.getDrawable(2));
            int primary = a.getColor(3, 0xff222222);
            a.recycle();
            mFrame.setStyle(Paint.Style.STROKE);
            mFrame.setStrokeWidth(dp(context, selected ? 2 : 1));
            mFrame.setColor(selected ? accent : (secondary & 0x00ffffff) | 0x80000000);
            mFill.setColor((accent & 0x00ffffff) | (selected ? 0x33000000 : 0));
            mText.setColor((primary & 0x00ffffff) | 0xb0000000);
            mAccent.setColor(accent);
            mBitmapPaint.setFilterBitmap(false);
            mBitmapPaint.setAntiAlias(false);
        }

        @Override protected void onMeasure(int widthSpec, int heightSpec) {
            int width = MeasureSpec.getSize(widthSpec);
            setMeasuredDimension(width, Math.min(width, mMaxSide));
        }

        @Override protected void onDraw(Canvas canvas) {
            float stroke = mFrame.getStrokeWidth();
            float side = Math.min(getWidth(), getHeight()) - stroke * 2;
            float left = (getWidth() - side) / 2f, top = (getHeight() - side) / 2f;
            float radius = dp(getContext(), 6);
            mRect.set(left, top, left + side, top + side);
            canvas.drawRoundRect(mRect, radius, radius, mFill);
            int inner = Math.round(side - stroke * 2);
            float ix = left + stroke, iy = top + stroke;
            if (mRender >= 1440) {
                canvas.save();
                canvas.translate(ix, iy);
                drawContent(canvas, inner);
                canvas.restore();
            } else {
                int n = Math.max(8, Math.round(inner * mRender / 2880f));
                if (mBitmap == null || mBitmap.getWidth() != n) {
                    mBitmap = Bitmap.createBitmap(n, n, Bitmap.Config.ARGB_8888);
                    Canvas c = new Canvas(mBitmap);
                    drawContent(c, n);
                }
                mRect.set(ix, iy, ix + inner, iy + inner);
                canvas.drawBitmap(mBitmap, null, mRect, mBitmapPaint);
            }
            canvas.drawRoundRect(rect(left, top, side), radius, radius, mFrame);
        }

        private RectF rect(float left, float top, float side) {
            mRect.set(left, top, left + side, top + side);
            return mRect;
        }

        /** Draws the screen content into a square of the given pixel size. */
        private void drawContent(Canvas c, float size) {
            float u = size / mContentDp;
            float bar = 28 * u, margin = 24 * u;
            c.drawRect(0, 0, size, bar, mAccent);
            float y = bar + margin;
            float dot = 48 * u;
            for (int k = 0; k < 4; k++) {
                c.drawCircle(margin + dot / 2 + k * 72 * u, y + dot / 2, dot / 2, mAccent);
            }
            y += dot + margin;
            float line = 16 * u, pitch = 36 * u, width = size - margin * 2;
            int i = 0;
            for (; y + line <= size - margin; y += pitch, i++) {
                mRect.set(margin, y, margin + width * WIDTHS[i % WIDTHS.length], y + line);
                c.drawRoundRect(mRect, line / 2, line / 2, mText);
            }
        }
    }
}
